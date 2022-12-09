// Copyright (c) 2015-2023 Vector 35 Inc
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

#include <cstring>
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


unordered_map<LowLevelILOperandUsage, LowLevelILOperandType> LowLevelILInstructionBase::operandTypeForUsage = {
    {SourceExprLowLevelOperandUsage, ExprLowLevelOperand},
    {SourceRegisterLowLevelOperandUsage, RegisterLowLevelOperand},
    {SourceRegisterStackLowLevelOperandUsage, RegisterStackLowLevelOperand},
    {SourceFlagLowLevelOperandUsage, FlagLowLevelOperand},
    {SourceSSARegisterLowLevelOperandUsage, SSARegisterLowLevelOperand},
    {SourceSSARegisterStackLowLevelOperandUsage, SSARegisterStackLowLevelOperand},
    {SourceSSAFlagLowLevelOperandUsage, SSAFlagLowLevelOperand}, {DestExprLowLevelOperandUsage, ExprLowLevelOperand},
    {DestRegisterLowLevelOperandUsage, RegisterLowLevelOperand},
    {DestRegisterStackLowLevelOperandUsage, RegisterStackLowLevelOperand},
    {DestFlagLowLevelOperandUsage, FlagLowLevelOperand},
    {DestSSARegisterLowLevelOperandUsage, SSARegisterLowLevelOperand},
    {DestSSARegisterStackLowLevelOperandUsage, SSARegisterStackLowLevelOperand},
    {DestSSAFlagLowLevelOperandUsage, SSAFlagLowLevelOperand},
    {SemanticFlagClassLowLevelOperandUsage, SemanticFlagClassLowLevelOperand},
    {SemanticFlagGroupLowLevelOperandUsage, SemanticFlagGroupLowLevelOperand},
    {PartialRegisterLowLevelOperandUsage, RegisterLowLevelOperand},
    {PartialSSARegisterStackSourceLowLevelOperandUsage, SSARegisterStackLowLevelOperand},
    {StackSSARegisterLowLevelOperandUsage, SSARegisterLowLevelOperand},
    {StackMemoryVersionLowLevelOperandUsage, IndexLowLevelOperand},
    {TopSSARegisterLowLevelOperandUsage, SSARegisterLowLevelOperand},
    {LeftExprLowLevelOperandUsage, ExprLowLevelOperand}, {RightExprLowLevelOperandUsage, ExprLowLevelOperand},
    {CarryExprLowLevelOperandUsage, ExprLowLevelOperand}, {ConditionExprLowLevelOperandUsage, ExprLowLevelOperand},
    {HighRegisterLowLevelOperandUsage, RegisterLowLevelOperand},
    {HighSSARegisterLowLevelOperandUsage, SSARegisterLowLevelOperand},
    {LowRegisterLowLevelOperandUsage, RegisterLowLevelOperand},
    {LowSSARegisterLowLevelOperandUsage, SSARegisterLowLevelOperand},
    {IntrinsicLowLevelOperandUsage, IntrinsicLowLevelOperand}, {ConstantLowLevelOperandUsage, IntegerLowLevelOperand},
    {VectorLowLevelOperandUsage, IntegerLowLevelOperand}, {StackAdjustmentLowLevelOperandUsage, IntegerLowLevelOperand},
    {TargetLowLevelOperandUsage, IndexLowLevelOperand}, {TrueTargetLowLevelOperandUsage, IndexLowLevelOperand},
    {FalseTargetLowLevelOperandUsage, IndexLowLevelOperand}, {BitIndexLowLevelOperandUsage, IndexLowLevelOperand},
    {SourceMemoryVersionLowLevelOperandUsage, IndexLowLevelOperand},
    {DestMemoryVersionLowLevelOperandUsage, IndexLowLevelOperand},
    {FlagConditionLowLevelOperandUsage, FlagConditionLowLevelOperand},
    {OutputSSARegistersLowLevelOperandUsage, SSARegisterListLowLevelOperand},
    {OutputMemoryVersionLowLevelOperandUsage, IndexLowLevelOperand},
    {ParameterExprsLowLevelOperandUsage, ExprListLowLevelOperand},
    {SourceSSARegistersLowLevelOperandUsage, SSARegisterListLowLevelOperand},
    {SourceSSARegisterStacksLowLevelOperandUsage, SSARegisterStackListLowLevelOperand},
    {SourceSSAFlagsLowLevelOperandUsage, SSAFlagListLowLevelOperand},
    {OutputRegisterOrFlagListLowLevelOperandUsage, RegisterOrFlagListLowLevelOperand},
    {OutputSSARegisterOrFlagListLowLevelOperandUsage, SSARegisterOrFlagListLowLevelOperand},
    {SourceMemoryVersionsLowLevelOperandUsage, IndexListLowLevelOperand},
    {TargetsLowLevelOperandUsage, IndexMapLowLevelOperand},
    {RegisterStackAdjustmentsLowLevelOperandUsage, RegisterStackAdjustmentsLowLevelOperand}};


unordered_map<BNLowLevelILOperation, vector<LowLevelILOperandUsage>> LowLevelILInstructionBase::operationOperandUsage =
    {{LLIL_NOP, {}}, {LLIL_POP, {}}, {LLIL_NORET, {}}, {LLIL_SYSCALL, {}}, {LLIL_BP, {}}, {LLIL_UNDEF, {}},
        {LLIL_UNIMPL, {}}, {LLIL_SET_REG, {DestRegisterLowLevelOperandUsage, SourceExprLowLevelOperandUsage}},
        {LLIL_SET_REG_SPLIT,
            {HighRegisterLowLevelOperandUsage, LowRegisterLowLevelOperandUsage, SourceExprLowLevelOperandUsage}},
        {LLIL_SET_REG_SSA, {DestSSARegisterLowLevelOperandUsage, SourceExprLowLevelOperandUsage}},
        {LLIL_SET_REG_SSA_PARTIAL,
            {DestSSARegisterLowLevelOperandUsage, PartialRegisterLowLevelOperandUsage, SourceExprLowLevelOperandUsage}},
        {LLIL_SET_REG_SPLIT_SSA,
            {HighSSARegisterLowLevelOperandUsage, LowSSARegisterLowLevelOperandUsage, SourceExprLowLevelOperandUsage}},
        {LLIL_SET_REG_STACK_REL,
            {DestRegisterStackLowLevelOperandUsage, DestExprLowLevelOperandUsage, SourceExprLowLevelOperandUsage}},
        {LLIL_REG_STACK_PUSH, {DestRegisterStackLowLevelOperandUsage, SourceExprLowLevelOperandUsage}},
        {LLIL_SET_REG_STACK_REL_SSA,
            {DestSSARegisterStackLowLevelOperandUsage, PartialSSARegisterStackSourceLowLevelOperandUsage,
                DestExprLowLevelOperandUsage, TopSSARegisterLowLevelOperandUsage, SourceExprLowLevelOperandUsage}},
        {LLIL_SET_REG_STACK_ABS_SSA,
            {DestSSARegisterStackLowLevelOperandUsage, PartialSSARegisterStackSourceLowLevelOperandUsage,
                DestRegisterLowLevelOperandUsage, SourceExprLowLevelOperandUsage}},
        {LLIL_SET_FLAG, {DestFlagLowLevelOperandUsage, SourceExprLowLevelOperandUsage}},
        {LLIL_SET_FLAG_SSA, {DestSSAFlagLowLevelOperandUsage, SourceExprLowLevelOperandUsage}},
        {LLIL_LOAD, {SourceExprLowLevelOperandUsage}},
        {LLIL_LOAD_SSA, {SourceExprLowLevelOperandUsage, SourceMemoryVersionLowLevelOperandUsage}},
        {LLIL_STORE, {DestExprLowLevelOperandUsage, SourceExprLowLevelOperandUsage}},
        {LLIL_STORE_SSA, {DestExprLowLevelOperandUsage, DestMemoryVersionLowLevelOperandUsage,
                             SourceMemoryVersionLowLevelOperandUsage, SourceExprLowLevelOperandUsage}},
        {LLIL_REG, {SourceRegisterLowLevelOperandUsage}}, {LLIL_REG_SSA, {SourceSSARegisterLowLevelOperandUsage}},
        {LLIL_REG_SSA_PARTIAL, {SourceSSARegisterLowLevelOperandUsage, PartialRegisterLowLevelOperandUsage}},
        {LLIL_REG_SPLIT, {HighRegisterLowLevelOperandUsage, LowRegisterLowLevelOperandUsage}},
        {LLIL_REG_SPLIT_SSA, {HighSSARegisterLowLevelOperandUsage, LowSSARegisterLowLevelOperandUsage}},
        {LLIL_REG_STACK_REL, {SourceRegisterStackLowLevelOperandUsage, SourceExprLowLevelOperandUsage}},
        {LLIL_REG_STACK_POP, {SourceRegisterStackLowLevelOperandUsage}},
        {LLIL_REG_STACK_FREE_REG, {DestRegisterLowLevelOperandUsage}},
        {LLIL_REG_STACK_FREE_REL, {DestRegisterStackLowLevelOperandUsage, DestExprLowLevelOperandUsage}},
        {LLIL_REG_STACK_REL_SSA, {SourceSSARegisterStackLowLevelOperandUsage, TopSSARegisterLowLevelOperandUsage,
                                     SourceExprLowLevelOperandUsage}},
        {LLIL_REG_STACK_ABS_SSA, {SourceSSARegisterStackLowLevelOperandUsage, SourceRegisterLowLevelOperandUsage}},
        {LLIL_REG_STACK_FREE_REL_SSA,
            {DestSSARegisterStackLowLevelOperandUsage, PartialSSARegisterStackSourceLowLevelOperandUsage,
                DestExprLowLevelOperandUsage, TopSSARegisterLowLevelOperandUsage}},
        {LLIL_REG_STACK_FREE_ABS_SSA,
            {DestSSARegisterStackLowLevelOperandUsage, PartialSSARegisterStackSourceLowLevelOperandUsage,
                DestRegisterLowLevelOperandUsage}},
        {LLIL_FLAG, {SourceFlagLowLevelOperandUsage}},
        {LLIL_FLAG_BIT, {SourceFlagLowLevelOperandUsage, BitIndexLowLevelOperandUsage}},
        {LLIL_FLAG_SSA, {SourceSSAFlagLowLevelOperandUsage}},
        {LLIL_FLAG_BIT_SSA, {SourceSSAFlagLowLevelOperandUsage, BitIndexLowLevelOperandUsage}},
        {LLIL_JUMP, {DestExprLowLevelOperandUsage}},
        {LLIL_JUMP_TO, {DestExprLowLevelOperandUsage, TargetsLowLevelOperandUsage}},
        {LLIL_CALL, {DestExprLowLevelOperandUsage}},
        {LLIL_CALL_STACK_ADJUST, {DestExprLowLevelOperandUsage, StackAdjustmentLowLevelOperandUsage,
                                     RegisterStackAdjustmentsLowLevelOperandUsage}},
        {LLIL_TAILCALL, {DestExprLowLevelOperandUsage}}, {LLIL_RET, {DestExprLowLevelOperandUsage}},
        {LLIL_IF, {ConditionExprLowLevelOperandUsage, TrueTargetLowLevelOperandUsage, FalseTargetLowLevelOperandUsage}},
        {LLIL_GOTO, {TargetLowLevelOperandUsage}},
        {LLIL_FLAG_COND, {FlagConditionLowLevelOperandUsage, SemanticFlagClassLowLevelOperandUsage}},
        {LLIL_FLAG_GROUP, {SemanticFlagGroupLowLevelOperandUsage}}, {LLIL_TRAP, {VectorLowLevelOperandUsage}},
        {LLIL_CALL_SSA, {OutputSSARegistersLowLevelOperandUsage, OutputMemoryVersionLowLevelOperandUsage,
                            DestExprLowLevelOperandUsage, StackSSARegisterLowLevelOperandUsage,
                            StackMemoryVersionLowLevelOperandUsage, ParameterExprsLowLevelOperandUsage}},
        {LLIL_SYSCALL_SSA, {OutputSSARegistersLowLevelOperandUsage, OutputMemoryVersionLowLevelOperandUsage,
                               StackSSARegisterLowLevelOperandUsage, StackMemoryVersionLowLevelOperandUsage,
                               ParameterExprsLowLevelOperandUsage}},
        {LLIL_TAILCALL_SSA, {OutputSSARegistersLowLevelOperandUsage, OutputMemoryVersionLowLevelOperandUsage,
                                DestExprLowLevelOperandUsage, StackSSARegisterLowLevelOperandUsage,
                                StackMemoryVersionLowLevelOperandUsage, ParameterExprsLowLevelOperandUsage}},
        {LLIL_REG_PHI, {DestSSARegisterLowLevelOperandUsage, SourceSSARegistersLowLevelOperandUsage}},
        {LLIL_REG_STACK_PHI, {DestSSARegisterStackLowLevelOperandUsage, SourceSSARegisterStacksLowLevelOperandUsage}},
        {LLIL_FLAG_PHI, {DestSSAFlagLowLevelOperandUsage, SourceSSAFlagsLowLevelOperandUsage}},
        {LLIL_MEM_PHI, {DestMemoryVersionLowLevelOperandUsage, SourceMemoryVersionsLowLevelOperandUsage}},
        {LLIL_CONST, {ConstantLowLevelOperandUsage}}, {LLIL_CONST_PTR, {ConstantLowLevelOperandUsage}},
        {LLIL_EXTERN_PTR, {ConstantLowLevelOperandUsage, OffsetLowLevelOperandUsage}},
        {LLIL_FLOAT_CONST, {ConstantLowLevelOperandUsage}},
        {LLIL_ADD, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_SUB, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_AND, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_OR, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_XOR, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_LSL, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_LSR, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_ASR, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_ROL, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_ROR, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_MUL, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_MULU_DP, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_MULS_DP, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_DIVU, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_DIVS, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_MODU, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_MODS, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_CMP_E, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_CMP_NE, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_CMP_SLT, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_CMP_ULT, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_CMP_SLE, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_CMP_ULE, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_CMP_SGE, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_CMP_UGE, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_CMP_SGT, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_CMP_UGT, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_TEST_BIT, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_ADD_OVERFLOW, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_ADC, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage, CarryExprLowLevelOperandUsage}},
        {LLIL_SBB, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage, CarryExprLowLevelOperandUsage}},
        {LLIL_RLC, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage, CarryExprLowLevelOperandUsage}},
        {LLIL_RRC, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage, CarryExprLowLevelOperandUsage}},
        {LLIL_DIVU_DP, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_DIVS_DP, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_MODU_DP, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_MODS_DP, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_PUSH, {SourceExprLowLevelOperandUsage}}, {LLIL_NEG, {SourceExprLowLevelOperandUsage}},
        {LLIL_NOT, {SourceExprLowLevelOperandUsage}}, {LLIL_SX, {SourceExprLowLevelOperandUsage}},
        {LLIL_ZX, {SourceExprLowLevelOperandUsage}}, {LLIL_LOW_PART, {SourceExprLowLevelOperandUsage}},
        {LLIL_BOOL_TO_INT, {SourceExprLowLevelOperandUsage}},
        {LLIL_INTRINSIC, {OutputRegisterOrFlagListLowLevelOperandUsage, IntrinsicLowLevelOperandUsage,
                             ParameterExprsLowLevelOperandUsage}},
        {LLIL_INTRINSIC_SSA, {OutputSSARegisterOrFlagListLowLevelOperandUsage, IntrinsicLowLevelOperandUsage,
                                 ParameterExprsLowLevelOperandUsage}},
        {LLIL_UNIMPL_MEM, {SourceExprLowLevelOperandUsage}},
        {LLIL_FADD, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_FSUB, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_FMUL, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_FDIV, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_FSQRT, {SourceExprLowLevelOperandUsage}}, {LLIL_FNEG, {SourceExprLowLevelOperandUsage}},
        {LLIL_FABS, {SourceExprLowLevelOperandUsage}}, {LLIL_FLOAT_TO_INT, {SourceExprLowLevelOperandUsage}},
        {LLIL_INT_TO_FLOAT, {SourceExprLowLevelOperandUsage}}, {LLIL_FLOAT_CONV, {SourceExprLowLevelOperandUsage}},
        {LLIL_ROUND_TO_INT, {SourceExprLowLevelOperandUsage}}, {LLIL_FLOOR, {SourceExprLowLevelOperandUsage}},
        {LLIL_CEIL, {SourceExprLowLevelOperandUsage}}, {LLIL_FTRUNC, {SourceExprLowLevelOperandUsage}},
        {LLIL_FCMP_E, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_FCMP_NE, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_FCMP_LT, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_FCMP_LE, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_FCMP_GE, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_FCMP_GT, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_FCMP_O, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}},
        {LLIL_FCMP_UO, {LeftExprLowLevelOperandUsage, RightExprLowLevelOperandUsage}}};


static unordered_map<BNLowLevelILOperation, unordered_map<LowLevelILOperandUsage, LLILOperandIndex>>
    GetOperandIndexForOperandUsages()
{
	unordered_map<BNLowLevelILOperation, unordered_map<LowLevelILOperandUsage, LLILOperandIndex>> result;
	result.reserve(LowLevelILInstructionBase::operationOperandUsage.size());
	for (auto& operation : LowLevelILInstructionBase::operationOperandUsage)
	{
		result[operation.first] = unordered_map<LowLevelILOperandUsage, LLILOperandIndex>();

		size_t operand = 0;
		result[operation.first].reserve(operation.second.size());
		for (auto usage : operation.second)
		{
			result[operation.first][usage] = LLILOperandIndex(operand);
			switch (usage)
			{
			case HighSSARegisterLowLevelOperandUsage:
			case LowSSARegisterLowLevelOperandUsage:
			case PartialSSARegisterStackSourceLowLevelOperandUsage:
			case TopSSARegisterLowLevelOperandUsage:
				// Represented as subexpression, so only takes one slot even though it is an SSA register
				operand++;
				break;
			case ParameterExprsLowLevelOperandUsage:
				// Represented as subexpression, so only takes one slot even though it is a list
				operand++;
				break;
			case OutputSSARegistersLowLevelOperandUsage:
				// OutputMemoryVersionLowLevelOperandUsage follows at same operand
				break;
			case StackSSARegisterLowLevelOperandUsage:
				// StackMemoryVersionLowLevelOperandUsage follows at same operand
				break;
			case DestSSARegisterStackLowLevelOperandUsage:
				// PartialSSARegisterStackSourceLowLevelOperandUsage follows at same operand
				break;
			default:
				switch (LowLevelILInstructionBase::operandTypeForUsage[usage])
				{
				case SSARegisterLowLevelOperand:
				case SSARegisterStackLowLevelOperand:
				case SSAFlagLowLevelOperand:
				case IndexListLowLevelOperand:
				case IndexMapLowLevelOperand:
				case SSARegisterListLowLevelOperand:
				case SSARegisterStackListLowLevelOperand:
				case SSAFlagListLowLevelOperand:
				case RegisterStackAdjustmentsLowLevelOperand:
				case RegisterOrFlagListLowLevelOperand:
				case SSARegisterOrFlagListLowLevelOperand:
					// SSA registers/flags and lists take two operand slots
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


unordered_map<BNLowLevelILOperation, unordered_map<LowLevelILOperandUsage, LLILOperandIndex>>
    LowLevelILInstructionBase::operationOperandIndex = GetOperandIndexForOperandUsages();


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


bool OperandIterator::operator==(const OperandIterator& a) const
{
	return count == a.count;
}


bool OperandIterator::operator!=(const OperandIterator& a) const
{
	return count != a.count;
}


bool OperandIterator::operator<(const OperandIterator& a) const
{
	return count > a.count;
}


OperandIterator& OperandIterator::operator++()
{
	count--;
	if (count == 0)
		return *this;

	operand++;
	if (operand >= 3)
	{
		operand = 0;
#ifdef BINARYNINJACORE_LIBRARY
		instr = &function->GetRawExpr(instr->operands[3].exprId);
#else
		instr = function->GetRawExpr(instr.operands[3].exprId);
#endif
	}
	return *this;
}


LLILRawOperand OperandIterator::operator*()
{
#ifdef BINARYNINJACORE_LIBRARY
	return instr->operands[operand];
#else
	return instr.operands[operand];
#endif
}


OperandList::OperandList(
    LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count)
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


OperandList::const_iterator OperandList::begin() const
{
	return m_start;
}


OperandList::const_iterator OperandList::end() const
{
	const_iterator result;
	result.function = m_start.function;
	result.operand = 0;
	result.count = 0;
	return result;
}


size_t OperandList::size() const
{
	return m_start.count;
}


LLILRawOperand OperandList::operator[](size_t i) const
{
	if (i >= size())
		throw LowLevelILInstructionAccessException();
	auto iter = begin();
	for (size_t j = 0; j < i; j++)
		++iter;
	return *iter;
}


OperandList::operator vector<LLILRawOperand>() const
{
	vector<LLILRawOperand> result;
	for (auto i : *this)
		result.push_back(i);
	return result;
}


LLILConstantInt LowLevelILIntegerList::ListIterator::operator*()
{
	return (*pos).GetConstant();
}


LowLevelILIntegerList::LowLevelILIntegerList(LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count) :
    m_list(func, instr, count)
{}


LowLevelILIntegerList::const_iterator LowLevelILIntegerList::begin() const
{
	const_iterator result;
	result.pos = m_list.begin();
	return result;
}


LowLevelILIntegerList::const_iterator LowLevelILIntegerList::end() const
{
	const_iterator result;
	result.pos = m_list.end();
	return result;
}


size_t LowLevelILIntegerList::size() const
{
	return m_list.size();
}


LLILConstantInt LowLevelILIntegerList::operator[](size_t i) const
{
	if (i >= size())
		throw LowLevelILInstructionAccessException();
	auto iter = begin();
	for (size_t j = 0; j < i; j++)
		++iter;
	return *iter;
}


LowLevelILIntegerList::operator vector<LLILConstantInt>() const
{
	vector<LLILConstantInt> result;
	for (auto i : *this)
		result.push_back(i);
	return result;
}


size_t LowLevelILIndexList::ListIterator::operator*()
{
	return (*pos).GetIndex();
}


LowLevelILIndexList::LowLevelILIndexList(LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count) :
    m_list(func, instr, count)
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
	for (auto i : *this)
		result.push_back(i);
	return result;
}


const pair<uint64_t, LLILLabelIndex> LowLevelILIndexMap::ListIterator::operator*()
{
	OperandList::const_iterator cur = pos;
	uint64_t value = (*cur).GetInteger();
	++cur;
	LLILLabelIndex target = (*cur).GetLabelIndex();
	return pair<uint64_t, LLILLabelIndex>(value, target);
}


LowLevelILIndexMap::LowLevelILIndexMap(LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count) :
    m_list(func, instr, count & (~1))
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


LLILLabelIndex LowLevelILIndexMap::operator[](uint64_t value) const
{
	for (auto iter = begin(); iter != end(); ++iter)
	{
		if ((*iter).first == value)
			return (*iter).second;
	}
	throw LowLevelILInstructionAccessException();
}


LowLevelILIndexMap::operator map<uint64_t, LLILLabelIndex>() const
{
	map<uint64_t, LLILLabelIndex> result;
	for (auto i : *this)
		result[i.first] = i.second;
	return result;
}


const LowLevelILInstruction LowLevelILInstructionList::ListIterator::operator*()
{
	return LowLevelILInstruction(
	    pos.GetFunction(), pos.GetFunction()->GetRawExpr((*pos).GetExprId()), (*pos).GetExprId(), instructionIndex);
}


LowLevelILInstructionList::LowLevelILInstructionList(
    LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count, LLILInstrId instrIndex) :
    m_list(func, instr, count),
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
	for (auto i : *this)
		result.push_back(i);
	return result;
}


const RegisterOrFlag LowLevelILRegisterOrFlagList::ListIterator::operator*()
{
	return (*pos).GetRegisterOrFlag();
}


LowLevelILRegisterOrFlagList::LowLevelILRegisterOrFlagList(
    LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count) :
    m_list(func, instr, count)
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
	for (auto i : *this)
		result.push_back(i);
	return result;
}


const SSARegister LowLevelILSSARegisterList::ListIterator::operator*()
{
	OperandList::const_iterator cur = pos;
	uint32_t reg = (*cur).GetRegister();
	++cur;
	size_t version = (*cur).GetVersion();
	return SSARegister(reg, version);
}


LowLevelILSSARegisterList::LowLevelILSSARegisterList(
    LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count) :
    m_list(func, instr, count & (~1))
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
	for (auto i : *this)
		result.push_back(i);
	return result;
}


const SSARegisterStack LowLevelILSSARegisterStackList::ListIterator::operator*()
{
	OperandList::const_iterator cur = pos;
	uint32_t regStack = (*cur).GetRegisterStack();
	++cur;
	size_t version = (*cur).GetVersion();
	return SSARegisterStack(regStack, version);
}


LowLevelILSSARegisterStackList::LowLevelILSSARegisterStackList(
    LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count) :
    m_list(func, instr, count & (~1))
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
	for (auto i : *this)
		result.push_back(i);
	return result;
}


const SSAFlag LowLevelILSSAFlagList::ListIterator::operator*()
{
	OperandList::const_iterator cur = pos;
	uint32_t flag = (*cur).GetFlag();
	++cur;
	size_t version = (*cur).GetVersion();
	return SSAFlag(flag, version);
}


LowLevelILSSAFlagList::LowLevelILSSAFlagList(
    LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count) :
    m_list(func, instr, count & (~1))
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
	for (auto i : *this)
		result.push_back(i);
	return result;
}


const SSARegisterOrFlag LowLevelILSSARegisterOrFlagList::ListIterator::operator*()
{
	OperandList::const_iterator cur = pos;
	RegisterOrFlag rf = (*cur).GetRegisterOrFlag();
	++cur;
	size_t version = (*cur).GetVersion();
	return SSARegisterOrFlag(rf, version);
}


LowLevelILSSARegisterOrFlagList::LowLevelILSSARegisterOrFlagList(
    LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count) :
    m_list(func, instr, count & (~1))
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
	for (auto i : *this)
		result.push_back(i);
	return result;
}


LowLevelILOperand::LowLevelILOperand(
    const LowLevelILInstruction& instr, LowLevelILOperandUsage usage, LLILOperandIndex operandIndex) :
    m_instr(instr),
    m_usage(usage), m_operandIndex(operandIndex)
{
	auto i = LowLevelILInstructionBase::operandTypeForUsage.find(m_usage);
	if (i == LowLevelILInstructionBase::operandTypeForUsage.end())
		throw LowLevelILInstructionAccessException();
	m_type = i->second;
}


uint64_t LowLevelILOperand::GetInteger() const
{
	if (m_type != IntegerLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsInteger(m_operandIndex);
}


size_t LowLevelILOperand::GetIndex() const
{
	if (m_type != IndexLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	if (m_usage == OutputMemoryVersionLowLevelOperandUsage)
		return m_instr.GetRawOperandAsExpr(m_operandIndex).GetRawOperandAsIndex(LLILOperandIndex(0));
	if (m_usage == StackMemoryVersionLowLevelOperandUsage)
		return m_instr.GetRawOperandAsExpr(m_operandIndex).GetRawOperandAsIndex(LLILOperandIndex(2));
	return m_instr.GetRawOperandAsIndex(m_operandIndex);
}


LowLevelILInstruction LowLevelILOperand::GetExpr() const
{
	if (m_type != ExprLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsExpr(m_operandIndex);
}


uint32_t LowLevelILOperand::GetRegister() const
{
	if (m_type != RegisterLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsRegister(m_operandIndex);
}


uint32_t LowLevelILOperand::GetRegisterStack() const
{
	if (m_type != RegisterStackLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsRegister(m_operandIndex);
}


uint32_t LowLevelILOperand::GetFlag() const
{
	if (m_type != FlagLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsRegister(m_operandIndex);
}


BNLowLevelILFlagCondition LowLevelILOperand::GetFlagCondition() const
{
	if (m_type != FlagConditionLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsFlagCondition(m_operandIndex);
}


uint32_t LowLevelILOperand::GetSemanticFlagClass() const
{
	if (m_type != SemanticFlagClassLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsRegister(m_operandIndex);
}


uint32_t LowLevelILOperand::GetSemanticFlagGroup() const
{
	if (m_type != SemanticFlagGroupLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsRegister(m_operandIndex);
}


uint32_t LowLevelILOperand::GetIntrinsic() const
{
	if (m_type != IntrinsicLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsRegister(m_operandIndex);
}


SSARegister LowLevelILOperand::GetSSARegister() const
{
	if (m_type != SSARegisterLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	if ((m_usage == HighSSARegisterLowLevelOperandUsage) || (m_usage == LowSSARegisterLowLevelOperandUsage)
	    || (m_usage == StackSSARegisterLowLevelOperandUsage) || (m_usage == TopSSARegisterLowLevelOperandUsage))
		return m_instr.GetRawOperandAsExpr(m_operandIndex).GetRawOperandAsSSARegister(LLILOperandIndex(0));
	return m_instr.GetRawOperandAsSSARegister(m_operandIndex);
}


SSARegisterStack LowLevelILOperand::GetSSARegisterStack() const
{
	if (m_type != SSARegisterStackLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	if (m_usage == DestSSARegisterStackLowLevelOperandUsage)
		return m_instr.GetRawOperandAsExpr(m_operandIndex).GetRawOperandAsSSARegisterStack(LLILOperandIndex(0));
	if (m_usage == PartialSSARegisterStackSourceLowLevelOperandUsage)
		return m_instr.GetRawOperandAsExpr(m_operandIndex).GetRawOperandAsPartialSSARegisterStackSource(LLILOperandIndex(0));
	return m_instr.GetRawOperandAsSSARegisterStack(m_operandIndex);
}


SSAFlag LowLevelILOperand::GetSSAFlag() const
{
	if (m_type != SSAFlagLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsSSAFlag(m_operandIndex);
}


LowLevelILIndexList LowLevelILOperand::GetIndexList() const
{
	if (m_type != IndexListLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsIndexList(m_operandIndex);
}


LowLevelILIndexMap LowLevelILOperand::GetIndexMap() const
{
	if (m_type != IndexMapLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsIndexMap(m_operandIndex);
}


LowLevelILInstructionList LowLevelILOperand::GetExprList() const
{
	if (m_type != ExprListLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsExpr(m_operandIndex).GetRawOperandAsExprList(LLILOperandIndex(0));
}


LowLevelILRegisterOrFlagList LowLevelILOperand::GetRegisterOrFlagList() const
{
	if (m_type != RegisterOrFlagListLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsRegisterOrFlagList(m_operandIndex);
}


LowLevelILSSARegisterList LowLevelILOperand::GetSSARegisterList() const
{
	if (m_type != SSARegisterListLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	if (m_usage == OutputSSARegistersLowLevelOperandUsage)
		return m_instr.GetRawOperandAsExpr(m_operandIndex).GetRawOperandAsSSARegisterList(LLILOperandIndex(1));
	return m_instr.GetRawOperandAsSSARegisterList(m_operandIndex);
}


LowLevelILSSARegisterStackList LowLevelILOperand::GetSSARegisterStackList() const
{
	if (m_type != SSARegisterStackListLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsSSARegisterStackList(m_operandIndex);
}


LowLevelILSSAFlagList LowLevelILOperand::GetSSAFlagList() const
{
	if (m_type != SSAFlagListLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsSSAFlagList(m_operandIndex);
}


LowLevelILSSARegisterOrFlagList LowLevelILOperand::GetSSARegisterOrFlagList() const
{
	if (m_type != SSARegisterOrFlagListLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsSSARegisterOrFlagList(m_operandIndex);
}


map<uint32_t, int32_t> LowLevelILOperand::GetRegisterStackAdjustments() const
{
	if (m_type != RegisterStackAdjustmentsLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsRegisterStackAdjustments(m_operandIndex);
}


const LowLevelILOperand LowLevelILOperandList::ListIterator::operator*()
{
	LowLevelILOperandUsage usage = *pos;
	auto i = owner->m_operandIndexMap.find(usage);
	if (i == owner->m_operandIndexMap.end())
		throw LowLevelILInstructionAccessException();
	return LowLevelILOperand(owner->m_instr, usage, i->second);
}


LowLevelILOperandList::LowLevelILOperandList(const LowLevelILInstruction& instr,
    const vector<LowLevelILOperandUsage>& usageList,
    const unordered_map<LowLevelILOperandUsage, LLILOperandIndex>& operandIndexMap) :
    m_instr(instr),
    m_usageList(usageList), m_operandIndexMap(operandIndexMap)
{}


LowLevelILOperandList::const_iterator LowLevelILOperandList::begin() const
{
	const_iterator result;
	result.owner = this;
	result.pos = m_usageList.begin();
	return result;
}


LowLevelILOperandList::const_iterator LowLevelILOperandList::end() const
{
	const_iterator result;
	result.owner = this;
	result.pos = m_usageList.end();
	return result;
}


size_t LowLevelILOperandList::size() const
{
	return m_usageList.size();
}


const LowLevelILOperand LowLevelILOperandList::operator[](LLILOperandIndex i) const
{
	LowLevelILOperandUsage usage = m_usageList[(size_t)i];
	auto indexMap = m_operandIndexMap.find(usage);
	if (indexMap == m_operandIndexMap.end())
		throw LowLevelILInstructionAccessException();
	return LowLevelILOperand(m_instr, usage, indexMap->second);
}


LowLevelILOperandList::operator vector<LowLevelILOperand>() const
{
	vector<LowLevelILOperand> result;
	for (auto i : *this)
		result.push_back(i);
	return result;
}


LowLevelILInstruction::LowLevelILInstruction()
{
	operation = LLIL_UNDEF;
	attributes = 0;
	sourceOperand = LLILOperandIndex::Invalid();
	size = 0;
	flags = 0;
	address = 0;
	function = nullptr;
	exprIndex = LLILExprId::Invalid();
	instructionIndex = LLILInstrId::Invalid();
}


LowLevelILInstruction::LowLevelILInstruction(
    LowLevelILFunction* func, const BNLowLevelILInstruction& instr, LLILExprId expr, LLILInstrId instrIdx)
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
	auto usage = operationOperandUsage.find(operation);
	if (usage == operationOperandUsage.end())
		throw LowLevelILInstructionAccessException();
	auto operandIndex = operationOperandIndex.find(operation);
	if (operandIndex == operationOperandIndex.end())
		throw LowLevelILInstructionAccessException();
	return LowLevelILOperandList(*(const LowLevelILInstruction*)this, usage->second, operandIndex->second);
}


LLILRawOperand LowLevelILInstructionBase::GetRawOperand(LLILOperandIndex operand) const
{
	return operands[(size_t)operand];
}


uint64_t LowLevelILInstructionBase::GetRawOperandAsInteger(LLILOperandIndex operand) const
{
	return GetRawOperand(operand).GetInteger();
}


size_t LowLevelILInstructionBase::GetRawOperandAsIndex(LLILOperandIndex operand) const
{
	return GetRawOperand(operand).GetIndex();
}


LLILLabelIndex LowLevelILInstructionBase::GetRawOperandAsLabelIndex(LLILOperandIndex operand) const
{
	return GetRawOperand(operand).GetLabelIndex();
}


uint32_t LowLevelILInstructionBase::GetRawOperandAsRegister(LLILOperandIndex operand) const
{
	return GetRawOperand(operand).GetRegister();
}


BNLowLevelILFlagCondition LowLevelILInstructionBase::GetRawOperandAsFlagCondition(LLILOperandIndex operand) const
{
	return GetRawOperand(operand).GetFlagCondition();
}


LowLevelILInstruction LowLevelILInstructionBase::GetRawOperandAsExpr(LLILOperandIndex operand) const
{
	return LowLevelILInstruction(
	    function, function->GetRawExpr(GetRawOperand(operand).GetExprId()), GetRawOperand(operand).GetExprId(), instructionIndex);
}


SSARegister LowLevelILInstructionBase::GetRawOperandAsSSARegister(LLILOperandIndex operand) const
{
	return SSARegister(GetRawOperand(operand).GetRegister(), GetRawOperand(LLILOperandIndex((size_t)operand + 1)).GetVersion());
}


SSARegisterStack LowLevelILInstructionBase::GetRawOperandAsSSARegisterStack(LLILOperandIndex operand) const
{
	return SSARegisterStack(GetRawOperand(operand).GetRegisterStack(), GetRawOperand(LLILOperandIndex((size_t)operand + 1)).GetVersion());
}


SSARegisterStack LowLevelILInstructionBase::GetRawOperandAsPartialSSARegisterStackSource(LLILOperandIndex operand) const
{
	return SSARegisterStack(GetRawOperand(operand).GetRegisterStack(), GetRawOperand(LLILOperandIndex((size_t)operand + 2)).GetVersion());
}


SSAFlag LowLevelILInstructionBase::GetRawOperandAsSSAFlag(LLILOperandIndex operand) const
{
	return SSAFlag(GetRawOperand(operand).GetFlag(), GetRawOperand(LLILOperandIndex((size_t)operand + 1)).GetVersion());
}


LowLevelILIndexList LowLevelILInstructionBase::GetRawOperandAsIndexList(LLILOperandIndex operand) const
{
	return LowLevelILIndexList(function, function->GetRawExpr(GetRawOperand(LLILOperandIndex((size_t)operand + 1)).GetExprId()), GetRawOperand(operand).GetCount());
}


LowLevelILIndexMap LowLevelILInstructionBase::GetRawOperandAsIndexMap(LLILOperandIndex operand) const
{
	return LowLevelILIndexMap(function, function->GetRawExpr(GetRawOperand(LLILOperandIndex((size_t)operand + 1)).GetExprId()), GetRawOperand(operand).GetCount());
}


LowLevelILInstructionList LowLevelILInstructionBase::GetRawOperandAsExprList(LLILOperandIndex operand) const
{
	return LowLevelILInstructionList(
	    function, function->GetRawExpr(GetRawOperand(LLILOperandIndex((size_t)operand + 1)).GetExprId()), GetRawOperand(operand).GetCount(), instructionIndex);
}


LowLevelILRegisterOrFlagList LowLevelILInstructionBase::GetRawOperandAsRegisterOrFlagList(LLILOperandIndex operand) const
{
	return LowLevelILRegisterOrFlagList(function, function->GetRawExpr(GetRawOperand(LLILOperandIndex((size_t)operand + 1)).GetExprId()), GetRawOperand(operand).GetCount());
}


LowLevelILSSARegisterList LowLevelILInstructionBase::GetRawOperandAsSSARegisterList(LLILOperandIndex operand) const
{
	return LowLevelILSSARegisterList(function, function->GetRawExpr(GetRawOperand(LLILOperandIndex((size_t)operand + 1)).GetExprId()), GetRawOperand(operand).GetCount());
}


LowLevelILSSARegisterStackList LowLevelILInstructionBase::GetRawOperandAsSSARegisterStackList(LLILOperandIndex operand) const
{
	return LowLevelILSSARegisterStackList(function, function->GetRawExpr(GetRawOperand(LLILOperandIndex((size_t)operand + 1)).GetExprId()), GetRawOperand(operand).GetCount());
}


LowLevelILSSAFlagList LowLevelILInstructionBase::GetRawOperandAsSSAFlagList(LLILOperandIndex operand) const
{
	return LowLevelILSSAFlagList(function, function->GetRawExpr(GetRawOperand(LLILOperandIndex((size_t)operand + 1)).GetExprId()), GetRawOperand(operand).GetCount());
}


LowLevelILSSARegisterOrFlagList LowLevelILInstructionBase::GetRawOperandAsSSARegisterOrFlagList(LLILOperandIndex operand) const
{
	return LowLevelILSSARegisterOrFlagList(function, function->GetRawExpr(GetRawOperand(LLILOperandIndex((size_t)operand + 1)).GetExprId()), GetRawOperand(operand).GetCount());
}


map<uint32_t, int32_t> LowLevelILInstructionBase::GetRawOperandAsRegisterStackAdjustments(LLILOperandIndex operand) const
{
	OperandList list(function, function->GetRawExpr(GetRawOperand(LLILOperandIndex((size_t)operand + 1)).GetExprId()), GetRawOperand(operand).GetCount());
	map<uint32_t, int32_t> result;
	for (auto i = list.begin(); i != list.end();)
	{
		uint32_t regStack = (*i).GetRegisterStack();
		++i;
		if (i == list.end())
			break;
		int32_t adjust = (*i).GetAdjustment();
		++i;
		result[regStack] = adjust;
	}
	return result;
}


void LowLevelILInstructionBase::UpdateRawOperand(LLILOperandIndex operandIndex, LLILRawOperand value)
{
	operands[(size_t)operandIndex] = value;
	function->UpdateInstructionOperand(exprIndex, operandIndex, value);
}


void LowLevelILInstructionBase::UpdateRawOperandAsSSARegisterList(LLILOperandIndex operandIndex, const vector<SSARegister>& regs)
{
	UpdateRawOperand(operandIndex, LLILRawOperand::FromCount(regs.size() * 2));
	UpdateRawOperand(LLILOperandIndex((size_t)operandIndex + 1), LLILRawOperand::FromExprId(function->AddSSARegisterList(regs)));
}


void LowLevelILInstructionBase::UpdateRawOperandAsSSARegisterOrFlagList(
    LLILOperandIndex operandIndex, const vector<SSARegisterOrFlag>& outputs)
{
	UpdateRawOperand(operandIndex, LLILRawOperand::FromCount(outputs.size() * 2));
	UpdateRawOperand(LLILOperandIndex((size_t)operandIndex + 1), LLILRawOperand::FromExprId(function->AddSSARegisterOrFlagList(outputs)));
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


LLILInstrId LowLevelILInstructionBase::GetSSAInstructionIndex() const
{
	return function->GetSSAInstructionIndex(instructionIndex);
}


LLILInstrId LowLevelILInstructionBase::GetNonSSAInstructionIndex() const
{
	return function->GetNonSSAInstructionIndex(instructionIndex);
}


LLILExprId LowLevelILInstructionBase::GetSSAExprIndex() const
{
	return function->GetSSAExprIndex(exprIndex);
}


LLILExprId LowLevelILInstructionBase::GetNonSSAExprIndex() const
{
	return function->GetNonSSAExprIndex(exprIndex);
}


LowLevelILInstruction LowLevelILInstructionBase::GetSSAForm() const
{
	Ref<LowLevelILFunction> ssa = function->GetSSAForm().GetPtr();
	if (!ssa)
		return *this;
	LLILExprId expr = GetSSAExprIndex();
	LLILInstrId instr = GetSSAInstructionIndex();
	return LowLevelILInstruction(ssa, ssa->GetRawExpr(expr), expr, instr);
}


LowLevelILInstruction LowLevelILInstructionBase::GetNonSSAForm() const
{
	Ref<LowLevelILFunction> nonSsa = function->GetNonSSAForm();
	if (!nonSsa)
		return *this;
	LLILExprId expr = GetNonSSAExprIndex();
	LLILInstrId instr = GetNonSSAInstructionIndex();
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
		if (exprIndex.IsValid() && ((size_t)exprIndex & 0xffff000000000000) == 0)
		{
			text += "[expr " + to_string((size_t)exprIndex) + "] ";
		}
		if (instructionIndex.IsValid() && ((size_t)instructionIndex & 0xffff000000000000) == 0)
		{
			text += "[instr " + to_string((size_t)instructionIndex) + "] ";
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


void LowLevelILInstructionBase::Replace(LLILExprId expr)
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


void LowLevelILInstruction::VisitExprs(const std::function<bool(const LowLevelILInstruction& expr)>& func) const
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
	case LLIL_SET_REG_SSA:
		GetSourceExpr<LLIL_SET_REG_SSA>().VisitExprs(func);
		break;
	case LLIL_SET_REG_SSA_PARTIAL:
		GetSourceExpr<LLIL_SET_REG_SSA_PARTIAL>().VisitExprs(func);
		break;
	case LLIL_SET_REG_SPLIT_SSA:
		GetSourceExpr<LLIL_SET_REG_SPLIT_SSA>().VisitExprs(func);
		break;
	case LLIL_SET_REG_STACK_REL:
		GetDestExpr<LLIL_SET_REG_STACK_REL>().VisitExprs(func);
		GetSourceExpr<LLIL_SET_REG_STACK_REL>().VisitExprs(func);
		break;
	case LLIL_REG_STACK_PUSH:
		GetSourceExpr<LLIL_REG_STACK_PUSH>().VisitExprs(func);
		break;
	case LLIL_SET_REG_STACK_REL_SSA:
		GetDestExpr<LLIL_SET_REG_STACK_REL_SSA>().VisitExprs(func);
		GetSourceExpr<LLIL_SET_REG_STACK_REL_SSA>().VisitExprs(func);
		break;
	case LLIL_SET_REG_STACK_ABS_SSA:
		GetSourceExpr<LLIL_SET_REG_STACK_ABS_SSA>().VisitExprs(func);
		break;
	case LLIL_SET_FLAG:
		GetSourceExpr<LLIL_SET_FLAG>().VisitExprs(func);
		break;
	case LLIL_SET_FLAG_SSA:
		GetSourceExpr<LLIL_SET_FLAG_SSA>().VisitExprs(func);
		break;
	case LLIL_REG_STACK_REL:
		GetSourceExpr<LLIL_REG_STACK_REL>().VisitExprs(func);
		break;
	case LLIL_REG_STACK_FREE_REL:
		GetDestExpr<LLIL_REG_STACK_FREE_REL>().VisitExprs(func);
		break;
	case LLIL_REG_STACK_REL_SSA:
		GetSourceExpr<LLIL_REG_STACK_REL_SSA>().VisitExprs(func);
		break;
	case LLIL_REG_STACK_FREE_REL_SSA:
		GetDestExpr<LLIL_REG_STACK_FREE_REL_SSA>().VisitExprs(func);
		break;
	case LLIL_LOAD:
		GetSourceExpr<LLIL_LOAD>().VisitExprs(func);
		break;
	case LLIL_LOAD_SSA:
		GetSourceExpr<LLIL_LOAD_SSA>().VisitExprs(func);
		break;
	case LLIL_STORE:
		GetDestExpr<LLIL_STORE>().VisitExprs(func);
		GetSourceExpr<LLIL_STORE>().VisitExprs(func);
		break;
	case LLIL_STORE_SSA:
		GetDestExpr<LLIL_STORE_SSA>().VisitExprs(func);
		GetSourceExpr<LLIL_STORE_SSA>().VisitExprs(func);
		break;
	case LLIL_JUMP:
		GetDestExpr<LLIL_JUMP>().VisitExprs(func);
		break;
	case LLIL_JUMP_TO:
		GetDestExpr<LLIL_JUMP_TO>().VisitExprs(func);
		break;
	case LLIL_IF:
		GetConditionExpr<LLIL_IF>().VisitExprs(func);
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
	case LLIL_CALL_SSA:
		GetDestExpr<LLIL_CALL_SSA>().VisitExprs(func);
		for (auto i : GetParameterExprs<LLIL_CALL_SSA>())
			i.VisitExprs(func);
		break;
	case LLIL_SYSCALL_SSA:
		for (auto i : GetParameterExprs<LLIL_SYSCALL_SSA>())
			i.VisitExprs(func);
		break;
	case LLIL_TAILCALL_SSA:
		GetDestExpr<LLIL_TAILCALL_SSA>().VisitExprs(func);
		for (auto i : GetParameterExprs<LLIL_TAILCALL_SSA>())
			i.VisitExprs(func);
		break;
	case LLIL_RET:
		GetDestExpr<LLIL_RET>().VisitExprs(func);
		break;
	case LLIL_PUSH:
	case LLIL_NEG:
	case LLIL_NOT:
	case LLIL_SX:
	case LLIL_ZX:
	case LLIL_LOW_PART:
	case LLIL_BOOL_TO_INT:
	case LLIL_UNIMPL_MEM:
	case LLIL_FSQRT:
	case LLIL_FNEG:
	case LLIL_FABS:
	case LLIL_FLOAT_TO_INT:
	case LLIL_INT_TO_FLOAT:
	case LLIL_FLOAT_CONV:
	case LLIL_ROUND_TO_INT:
	case LLIL_FLOOR:
	case LLIL_CEIL:
	case LLIL_FTRUNC:
		AsOneOperand().GetSourceExpr().VisitExprs(func);
		break;
	case LLIL_ADD:
	case LLIL_SUB:
	case LLIL_AND:
	case LLIL_OR:
	case LLIL_XOR:
	case LLIL_LSL:
	case LLIL_LSR:
	case LLIL_ASR:
	case LLIL_ROL:
	case LLIL_ROR:
	case LLIL_MUL:
	case LLIL_MULU_DP:
	case LLIL_MULS_DP:
	case LLIL_DIVU:
	case LLIL_DIVS:
	case LLIL_MODU:
	case LLIL_MODS:
	case LLIL_DIVU_DP:
	case LLIL_DIVS_DP:
	case LLIL_MODU_DP:
	case LLIL_MODS_DP:
	case LLIL_CMP_E:
	case LLIL_CMP_NE:
	case LLIL_CMP_SLT:
	case LLIL_CMP_ULT:
	case LLIL_CMP_SLE:
	case LLIL_CMP_ULE:
	case LLIL_CMP_SGE:
	case LLIL_CMP_UGE:
	case LLIL_CMP_SGT:
	case LLIL_CMP_UGT:
	case LLIL_TEST_BIT:
	case LLIL_ADD_OVERFLOW:
	case LLIL_FADD:
	case LLIL_FSUB:
	case LLIL_FMUL:
	case LLIL_FDIV:
	case LLIL_FCMP_E:
	case LLIL_FCMP_NE:
	case LLIL_FCMP_LT:
	case LLIL_FCMP_LE:
	case LLIL_FCMP_GE:
	case LLIL_FCMP_GT:
	case LLIL_FCMP_O:
	case LLIL_FCMP_UO:
		AsTwoOperand().GetLeftExpr().VisitExprs(func);
		AsTwoOperand().GetRightExpr().VisitExprs(func);
		break;
	case LLIL_ADC:
	case LLIL_SBB:
	case LLIL_RLC:
	case LLIL_RRC:
		AsTwoOperandWithCarry().GetLeftExpr().VisitExprs(func);
		AsTwoOperandWithCarry().GetRightExpr().VisitExprs(func);
		AsTwoOperandWithCarry().GetCarryExpr().VisitExprs(func);
		break;
	case LLIL_INTRINSIC:
		for (auto i : GetParameterExprs<LLIL_INTRINSIC>())
			i.VisitExprs(func);
		break;
	case LLIL_INTRINSIC_SSA:
		for (auto i : GetParameterExprs<LLIL_INTRINSIC_SSA>())
			i.VisitExprs(func);
		break;
	default:
		break;
	}
}


LLILExprId LowLevelILInstruction::CopyTo(LowLevelILFunction* dest) const
{
	return CopyTo(dest, [&](const LowLevelILInstruction& subExpr) { return subExpr.CopyTo(dest); });
}


LLILExprId LowLevelILInstruction::CopyTo(
    LowLevelILFunction* dest, const std::function<LLILExprId(const LowLevelILInstruction& subExpr)>& subExprHandler) const
{
	vector<LLILExprId> params;
	BNLowLevelILLabel* labelA;
	BNLowLevelILLabel* labelB;
	switch (operation)
	{
	case LLIL_NOP:
		return dest->Nop();
	case LLIL_SET_REG:
		return dest->SetRegister(
		    size, GetDestRegister<LLIL_SET_REG>(), subExprHandler(GetSourceExpr<LLIL_SET_REG>()), flags, *this);
	case LLIL_SET_REG_SPLIT:
		return dest->SetRegisterSplit(size, GetHighRegister<LLIL_SET_REG_SPLIT>(), GetLowRegister<LLIL_SET_REG_SPLIT>(),
		    subExprHandler(GetSourceExpr<LLIL_SET_REG_SPLIT>()), flags, *this);
	case LLIL_SET_REG_SSA:
		return dest->SetRegisterSSA(
		    size, GetDestSSARegister<LLIL_SET_REG_SSA>(), subExprHandler(GetSourceExpr<LLIL_SET_REG_SSA>()), *this);
	case LLIL_SET_REG_SSA_PARTIAL:
		return dest->SetRegisterSSAPartial(size, GetDestSSARegister<LLIL_SET_REG_SSA_PARTIAL>(),
		    GetPartialRegister<LLIL_SET_REG_SSA_PARTIAL>(), subExprHandler(GetSourceExpr<LLIL_SET_REG_SSA_PARTIAL>()),
		    *this);
	case LLIL_SET_REG_SPLIT_SSA:
		return dest->SetRegisterSplitSSA(size, GetHighSSARegister<LLIL_SET_REG_SPLIT_SSA>(),
		    GetLowSSARegister<LLIL_SET_REG_SPLIT_SSA>(), subExprHandler(GetSourceExpr<LLIL_SET_REG_SPLIT_SSA>()),
		    *this);
	case LLIL_SET_REG_STACK_REL:
		return dest->SetRegisterStackTopRelative(size, GetDestRegisterStack<LLIL_SET_REG_STACK_REL>(),
		    subExprHandler(GetDestExpr<LLIL_SET_REG_STACK_REL>()),
		    subExprHandler(GetSourceExpr<LLIL_SET_REG_STACK_REL>()), flags, *this);
	case LLIL_REG_STACK_PUSH:
		return dest->RegisterStackPush(size, GetDestRegisterStack<LLIL_REG_STACK_PUSH>(),
		    subExprHandler(GetSourceExpr<LLIL_REG_STACK_PUSH>()), flags, *this);
	case LLIL_SET_REG_STACK_REL_SSA:
		return dest->SetRegisterStackTopRelativeSSA(size,
		    GetDestSSARegisterStack<LLIL_SET_REG_STACK_REL_SSA>().regStack,
		    GetDestSSARegisterStack<LLIL_SET_REG_STACK_REL_SSA>().version,
		    GetSourceSSARegisterStack<LLIL_SET_REG_STACK_REL_SSA>().version,
		    subExprHandler(GetDestExpr<LLIL_SET_REG_STACK_REL_SSA>()), GetTopSSARegister<LLIL_SET_REG_STACK_REL_SSA>(),
		    subExprHandler(GetSourceExpr<LLIL_SET_REG_STACK_REL_SSA>()), *this);
	case LLIL_SET_REG_STACK_ABS_SSA:
		return dest->SetRegisterStackAbsoluteSSA(size, GetDestSSARegisterStack<LLIL_SET_REG_STACK_ABS_SSA>().regStack,
		    GetDestSSARegisterStack<LLIL_SET_REG_STACK_ABS_SSA>().version,
		    GetSourceSSARegisterStack<LLIL_SET_REG_STACK_ABS_SSA>().version,
		    GetDestRegister<LLIL_SET_REG_STACK_ABS_SSA>(), subExprHandler(GetSourceExpr<LLIL_SET_REG_STACK_ABS_SSA>()),
		    *this);
	case LLIL_SET_FLAG:
		return dest->SetFlag(GetDestFlag<LLIL_SET_FLAG>(), subExprHandler(GetSourceExpr<LLIL_SET_FLAG>()), *this);
	case LLIL_SET_FLAG_SSA:
		return dest->SetFlagSSA(
		    GetDestSSAFlag<LLIL_SET_FLAG_SSA>(), subExprHandler(GetSourceExpr<LLIL_SET_FLAG_SSA>()), *this);
	case LLIL_LOAD:
		return dest->Load(size, subExprHandler(GetSourceExpr<LLIL_LOAD>()), flags, *this);
	case LLIL_LOAD_SSA:
		return dest->LoadSSA(
		    size, subExprHandler(GetSourceExpr<LLIL_LOAD_SSA>()), GetSourceMemoryVersion<LLIL_LOAD_SSA>(), *this);
	case LLIL_STORE:
		return dest->Store(
		    size, subExprHandler(GetDestExpr<LLIL_STORE>()), subExprHandler(GetSourceExpr<LLIL_STORE>()), flags, *this);
	case LLIL_STORE_SSA:
		return dest->StoreSSA(size, subExprHandler(GetDestExpr<LLIL_STORE_SSA>()),
		    subExprHandler(GetSourceExpr<LLIL_STORE_SSA>()), GetDestMemoryVersion<LLIL_STORE_SSA>(),
		    GetSourceMemoryVersion<LLIL_STORE_SSA>(), *this);
	case LLIL_REG:
		return dest->Register(size, GetSourceRegister<LLIL_REG>(), *this);
	case LLIL_REG_SSA:
		return dest->RegisterSSA(size, GetSourceSSARegister<LLIL_REG_SSA>(), *this);
	case LLIL_REG_SSA_PARTIAL:
		return dest->RegisterSSAPartial(
		    size, GetSourceSSARegister<LLIL_REG_SSA_PARTIAL>(), GetPartialRegister<LLIL_REG_SSA_PARTIAL>(), *this);
	case LLIL_REG_SPLIT:
		return dest->RegisterSplit(size, GetHighRegister<LLIL_REG_SPLIT>(), GetLowRegister<LLIL_REG_SPLIT>(), *this);
	case LLIL_REG_SPLIT_SSA:
		return dest->RegisterSplitSSA(
		    size, GetHighSSARegister<LLIL_REG_SPLIT_SSA>(), GetLowSSARegister<LLIL_REG_SPLIT_SSA>(), *this);
	case LLIL_REG_STACK_REL:
		return dest->RegisterStackTopRelative(size, GetSourceRegisterStack<LLIL_REG_STACK_REL>(),
		    subExprHandler(GetSourceExpr<LLIL_REG_STACK_REL>()), *this);
	case LLIL_REG_STACK_POP:
		return dest->RegisterStackPop(size, GetSourceRegisterStack<LLIL_REG_STACK_POP>(), flags, *this);
	case LLIL_REG_STACK_FREE_REG:
		return dest->RegisterStackFreeReg(GetDestRegister<LLIL_REG_STACK_FREE_REG>(), *this);
	case LLIL_REG_STACK_FREE_REL:
		return dest->RegisterStackFreeTopRelative(GetDestRegisterStack<LLIL_REG_STACK_FREE_REL>(),
		    subExprHandler(GetDestExpr<LLIL_REG_STACK_FREE_REL>()), *this);
	case LLIL_REG_STACK_REL_SSA:
		return dest->RegisterStackTopRelativeSSA(size, GetSourceSSARegisterStack<LLIL_REG_STACK_REL_SSA>(),
		    subExprHandler(GetSourceExpr<LLIL_REG_STACK_REL_SSA>()), GetTopSSARegister<LLIL_REG_STACK_REL_SSA>(),
		    *this);
	case LLIL_REG_STACK_ABS_SSA:
		return dest->RegisterStackAbsoluteSSA(size, GetSourceSSARegisterStack<LLIL_REG_STACK_ABS_SSA>(),
		    GetSourceRegister<LLIL_REG_STACK_ABS_SSA>(), *this);
	case LLIL_REG_STACK_FREE_REL_SSA:
		return dest->RegisterStackFreeTopRelativeSSA(GetDestSSARegisterStack<LLIL_REG_STACK_FREE_REL_SSA>().regStack,
		    GetDestSSARegisterStack<LLIL_REG_STACK_FREE_REL_SSA>().version,
		    GetSourceSSARegisterStack<LLIL_REG_STACK_FREE_REL_SSA>().version,
		    subExprHandler(GetDestExpr<LLIL_REG_STACK_FREE_REL_SSA>()),
		    GetTopSSARegister<LLIL_REG_STACK_FREE_REL_SSA>(), *this);
	case LLIL_REG_STACK_FREE_ABS_SSA:
		return dest->RegisterStackFreeAbsoluteSSA(GetDestSSARegisterStack<LLIL_REG_STACK_FREE_ABS_SSA>().regStack,
		    GetDestSSARegisterStack<LLIL_REG_STACK_FREE_ABS_SSA>().version,
		    GetSourceSSARegisterStack<LLIL_REG_STACK_FREE_ABS_SSA>().version,
		    GetDestRegister<LLIL_REG_STACK_FREE_ABS_SSA>(), *this);
	case LLIL_FLAG:
		return dest->Flag(GetSourceFlag<LLIL_FLAG>(), *this);
	case LLIL_FLAG_SSA:
		return dest->FlagSSA(GetSourceSSAFlag<LLIL_FLAG_SSA>(), *this);
	case LLIL_FLAG_BIT:
		return dest->FlagBit(size, GetSourceFlag<LLIL_FLAG_BIT>(), GetBitIndex<LLIL_FLAG_BIT>(), *this);
	case LLIL_FLAG_BIT_SSA:
		return dest->FlagBitSSA(size, GetSourceSSAFlag<LLIL_FLAG_BIT_SSA>(), GetBitIndex<LLIL_FLAG_BIT_SSA>(), *this);
	case LLIL_JUMP:
		return dest->Jump(subExprHandler(GetDestExpr<LLIL_JUMP>()), *this);
	case LLIL_CALL:
		return dest->Call(subExprHandler(GetDestExpr<LLIL_CALL>()), *this);
	case LLIL_CALL_STACK_ADJUST:
		return dest->CallStackAdjust(subExprHandler(GetDestExpr<LLIL_CALL_STACK_ADJUST>()),
		    GetStackAdjustment<LLIL_CALL_STACK_ADJUST>(), GetRegisterStackAdjustments<LLIL_CALL_STACK_ADJUST>(), *this);
	case LLIL_TAILCALL:
		return dest->TailCall(subExprHandler(GetDestExpr<LLIL_TAILCALL>()), *this);
	case LLIL_RET:
		return dest->Return(subExprHandler(GetDestExpr<LLIL_RET>()), *this);
	case LLIL_JUMP_TO:
	{
		map<uint64_t, BNLowLevelILLabel*> labelList;
		for (auto target : GetTargets<LLIL_JUMP_TO>())
		{
			labelA = dest->GetLabelForSourceInstruction(target.second);
			if (!labelA)
				return dest->Jump(subExprHandler(GetDestExpr<LLIL_JUMP_TO>()), *this);
			labelList[target.first] = labelA;
		}
		return dest->JumpTo(subExprHandler(GetDestExpr<LLIL_JUMP_TO>()), labelList, *this);
	}
	case LLIL_GOTO:
		labelA = dest->GetLabelForSourceInstruction(GetTarget<LLIL_GOTO>());
		if (!labelA)
		{
			return dest->Jump(dest->ConstPointer(function->GetArchitecture()->GetAddressSize(),
			                      function->GetInstruction(GetTarget<LLIL_GOTO>()).address),
			    *this);
		}
		return dest->Goto(*labelA, *this);
	case LLIL_IF:
		labelA = dest->GetLabelForSourceInstruction(GetTrueTarget<LLIL_IF>());
		labelB = dest->GetLabelForSourceInstruction(GetFalseTarget<LLIL_IF>());
		if ((!labelA) || (!labelB))
			return dest->Undefined(*this);
		return dest->If(subExprHandler(GetConditionExpr<LLIL_IF>()), *labelA, *labelB, *this);
	case LLIL_FLAG_COND:
		return dest->FlagCondition(GetFlagCondition<LLIL_FLAG_COND>(), GetSemanticFlagClass<LLIL_FLAG_COND>(), *this);
	case LLIL_FLAG_GROUP:
		return dest->FlagGroup(GetSemanticFlagGroup<LLIL_FLAG_GROUP>(), *this);
	case LLIL_TRAP:
		return dest->Trap(GetVector<LLIL_TRAP>(), *this);
	case LLIL_CALL_SSA:
		for (auto i : GetParameterExprs<LLIL_CALL_SSA>())
			params.push_back(subExprHandler(i));
		return dest->CallSSA(GetOutputSSARegisters<LLIL_CALL_SSA>(), subExprHandler(GetDestExpr<LLIL_CALL_SSA>()),
		    params, GetStackSSARegister<LLIL_CALL_SSA>(), GetDestMemoryVersion<LLIL_CALL_SSA>(),
		    GetSourceMemoryVersion<LLIL_CALL_SSA>(), *this);
	case LLIL_SYSCALL_SSA:
		for (auto i : GetParameterExprs<LLIL_SYSCALL_SSA>())
			params.push_back(subExprHandler(i));
		return dest->SystemCallSSA(GetOutputSSARegisters<LLIL_SYSCALL_SSA>(), params,
		    GetStackSSARegister<LLIL_SYSCALL_SSA>(), GetDestMemoryVersion<LLIL_SYSCALL_SSA>(),
		    GetSourceMemoryVersion<LLIL_SYSCALL_SSA>(), *this);
	case LLIL_TAILCALL_SSA:
		for (auto i : GetParameterExprs<LLIL_TAILCALL_SSA>())
			params.push_back(subExprHandler(i));
		return dest->TailCallSSA(GetOutputSSARegisters<LLIL_TAILCALL_SSA>(),
		    subExprHandler(GetDestExpr<LLIL_TAILCALL_SSA>()), params, GetStackSSARegister<LLIL_TAILCALL_SSA>(),
		    GetDestMemoryVersion<LLIL_TAILCALL_SSA>(), GetSourceMemoryVersion<LLIL_TAILCALL_SSA>(), *this);
	case LLIL_REG_PHI:
		return dest->RegisterPhi(GetDestSSARegister<LLIL_REG_PHI>(), GetSourceSSARegisters<LLIL_REG_PHI>(), *this);
	case LLIL_REG_STACK_PHI:
		return dest->RegisterStackPhi(
		    GetDestSSARegisterStack<LLIL_REG_STACK_PHI>(), GetSourceSSARegisterStacks<LLIL_REG_STACK_PHI>(), *this);
	case LLIL_FLAG_PHI:
		return dest->FlagPhi(GetDestSSAFlag<LLIL_FLAG_PHI>(), GetSourceSSAFlags<LLIL_FLAG_PHI>(), *this);
	case LLIL_MEM_PHI:
		return dest->MemoryPhi(GetDestMemoryVersion<LLIL_MEM_PHI>(), GetSourceMemoryVersions<LLIL_MEM_PHI>(), *this);
	case LLIL_CONST:
		return dest->Const(size, GetConstant<LLIL_CONST>(), *this);
	case LLIL_CONST_PTR:
		return dest->ConstPointer(size, GetConstant<LLIL_CONST_PTR>(), *this);
	case LLIL_EXTERN_PTR:
		return dest->ExternPointer(size, GetConstant<LLIL_EXTERN_PTR>(), GetOffset<LLIL_EXTERN_PTR>(), *this);
	case LLIL_FLOAT_CONST:
		return dest->FloatConstRaw(size, GetConstant<LLIL_FLOAT_CONST>(), *this);
	case LLIL_POP:
	case LLIL_NORET:
	case LLIL_SYSCALL:
	case LLIL_BP:
	case LLIL_UNDEF:
	case LLIL_UNIMPL:
		return dest->AddExprWithLocation(operation, *this, size, flags);
	case LLIL_PUSH:
	case LLIL_NEG:
	case LLIL_NOT:
	case LLIL_SX:
	case LLIL_ZX:
	case LLIL_LOW_PART:
	case LLIL_BOOL_TO_INT:
	case LLIL_UNIMPL_MEM:
	case LLIL_FSQRT:
	case LLIL_FNEG:
	case LLIL_FABS:
	case LLIL_FLOAT_TO_INT:
	case LLIL_INT_TO_FLOAT:
	case LLIL_FLOAT_CONV:
	case LLIL_ROUND_TO_INT:
	case LLIL_FLOOR:
	case LLIL_CEIL:
	case LLIL_FTRUNC:
		return dest->AddExprWithLocation(operation, *this, size, flags, LLILRawOperand::FromExprId(subExprHandler(AsOneOperand().GetSourceExpr())));
	case LLIL_ADD:
	case LLIL_SUB:
	case LLIL_AND:
	case LLIL_OR:
	case LLIL_XOR:
	case LLIL_LSL:
	case LLIL_LSR:
	case LLIL_ASR:
	case LLIL_ROL:
	case LLIL_ROR:
	case LLIL_MUL:
	case LLIL_MULU_DP:
	case LLIL_MULS_DP:
	case LLIL_DIVU:
	case LLIL_DIVS:
	case LLIL_MODU:
	case LLIL_MODS:
	case LLIL_DIVU_DP:
	case LLIL_DIVS_DP:
	case LLIL_MODU_DP:
	case LLIL_MODS_DP:
	case LLIL_CMP_E:
	case LLIL_CMP_NE:
	case LLIL_CMP_SLT:
	case LLIL_CMP_ULT:
	case LLIL_CMP_SLE:
	case LLIL_CMP_ULE:
	case LLIL_CMP_SGE:
	case LLIL_CMP_UGE:
	case LLIL_CMP_SGT:
	case LLIL_CMP_UGT:
	case LLIL_TEST_BIT:
	case LLIL_ADD_OVERFLOW:
	case LLIL_FADD:
	case LLIL_FSUB:
	case LLIL_FMUL:
	case LLIL_FDIV:
	case LLIL_FCMP_E:
	case LLIL_FCMP_NE:
	case LLIL_FCMP_LT:
	case LLIL_FCMP_LE:
	case LLIL_FCMP_GE:
	case LLIL_FCMP_GT:
	case LLIL_FCMP_O:
	case LLIL_FCMP_UO:
		return dest->AddExprWithLocation(operation, *this, size, flags, LLILRawOperand::FromExprId(subExprHandler(AsTwoOperand().GetLeftExpr())),
		    LLILRawOperand::FromExprId(subExprHandler(AsTwoOperand().GetRightExpr())));
	case LLIL_ADC:
	case LLIL_SBB:
	case LLIL_RLC:
	case LLIL_RRC:
		return dest->AddExprWithLocation(operation, *this, size, flags,
		    LLILRawOperand::FromExprId(subExprHandler(AsTwoOperandWithCarry().GetLeftExpr())),
		    LLILRawOperand::FromExprId(subExprHandler(AsTwoOperandWithCarry().GetRightExpr())),
		    LLILRawOperand::FromExprId(subExprHandler(AsTwoOperandWithCarry().GetCarryExpr())));
	case LLIL_INTRINSIC:
		for (auto i : GetParameterExprs<LLIL_INTRINSIC>())
			params.push_back(subExprHandler(i));
		return dest->Intrinsic(
		    GetOutputRegisterOrFlagList<LLIL_INTRINSIC>(), GetIntrinsic<LLIL_INTRINSIC>(), params, flags, *this);
	case LLIL_INTRINSIC_SSA:
		for (auto i : GetParameterExprs<LLIL_INTRINSIC_SSA>())
			params.push_back(subExprHandler(i));
		return dest->IntrinsicSSA(
		    GetOutputSSARegisterOrFlagList<LLIL_INTRINSIC_SSA>(), GetIntrinsic<LLIL_INTRINSIC_SSA>(), params, *this);
	default:
		throw LowLevelILInstructionAccessException();
	}
}


bool LowLevelILInstruction::GetOperandIndexForUsage(LowLevelILOperandUsage usage, LLILOperandIndex& operandIndex) const
{
	auto operationIter = LowLevelILInstructionBase::operationOperandIndex.find(operation);
	if (operationIter == LowLevelILInstructionBase::operationOperandIndex.end())
		return false;
	auto usageIter = operationIter->second.find(usage);
	if (usageIter == operationIter->second.end())
		return false;
	operandIndex = usageIter->second;
	return true;
}


LowLevelILInstruction LowLevelILInstruction::GetSourceExpr() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(SourceExprLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw LowLevelILInstructionAccessException();
}


uint32_t LowLevelILInstruction::GetSourceRegister() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(SourceRegisterLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsRegister(operandIndex);
	throw LowLevelILInstructionAccessException();
}


uint32_t LowLevelILInstruction::GetSourceRegisterStack() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(SourceRegisterStackLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsRegister(operandIndex);
	throw LowLevelILInstructionAccessException();
}


uint32_t LowLevelILInstruction::GetSourceFlag() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(SourceFlagLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsRegister(operandIndex);
	throw LowLevelILInstructionAccessException();
}


SSARegister LowLevelILInstruction::GetSourceSSARegister() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(SourceSSARegisterLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsSSARegister(operandIndex);
	throw LowLevelILInstructionAccessException();
}


SSARegisterStack LowLevelILInstruction::GetSourceSSARegisterStack() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(PartialSSARegisterStackSourceLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex).GetRawOperandAsPartialSSARegisterStackSource(LLILOperandIndex(0));
	if (GetOperandIndexForUsage(SourceSSARegisterStackLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsSSARegisterStack(operandIndex);
	throw LowLevelILInstructionAccessException();
}


SSAFlag LowLevelILInstruction::GetSourceSSAFlag() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(SourceSSAFlagLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsSSAFlag(operandIndex);
	throw LowLevelILInstructionAccessException();
}


LowLevelILInstruction LowLevelILInstruction::GetDestExpr() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(DestExprLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw LowLevelILInstructionAccessException();
}


uint32_t LowLevelILInstruction::GetDestRegister() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(DestRegisterLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsRegister(operandIndex);
	throw LowLevelILInstructionAccessException();
}


uint32_t LowLevelILInstruction::GetDestRegisterStack() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(DestRegisterStackLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsRegister(operandIndex);
	throw LowLevelILInstructionAccessException();
}


uint32_t LowLevelILInstruction::GetDestFlag() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(DestFlagLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsRegister(operandIndex);
	throw LowLevelILInstructionAccessException();
}


SSARegister LowLevelILInstruction::GetDestSSARegister() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(DestSSARegisterLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsSSARegister(operandIndex);
	throw LowLevelILInstructionAccessException();
}


SSARegisterStack LowLevelILInstruction::GetDestSSARegisterStack() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(DestSSARegisterStackLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex).GetRawOperandAsSSARegisterStack(LLILOperandIndex(0));
	throw LowLevelILInstructionAccessException();
}


SSAFlag LowLevelILInstruction::GetDestSSAFlag() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(DestSSAFlagLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsSSAFlag(operandIndex);
	throw LowLevelILInstructionAccessException();
}


uint32_t LowLevelILInstruction::GetSemanticFlagClass() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(SemanticFlagClassLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsRegister(operandIndex);
	throw LowLevelILInstructionAccessException();
}


uint32_t LowLevelILInstruction::GetSemanticFlagGroup() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(SemanticFlagGroupLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsRegister(operandIndex);
	throw LowLevelILInstructionAccessException();
}


uint32_t LowLevelILInstruction::GetPartialRegister() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(PartialRegisterLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsRegister(operandIndex);
	throw LowLevelILInstructionAccessException();
}


SSARegister LowLevelILInstruction::GetStackSSARegister() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(StackSSARegisterLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex).GetRawOperandAsSSARegister(LLILOperandIndex(0));
	throw LowLevelILInstructionAccessException();
}


SSARegister LowLevelILInstruction::GetTopSSARegister() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(TopSSARegisterLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex).GetRawOperandAsSSARegister(LLILOperandIndex(0));
	throw LowLevelILInstructionAccessException();
}


LowLevelILInstruction LowLevelILInstruction::GetLeftExpr() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(LeftExprLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw LowLevelILInstructionAccessException();
}


LowLevelILInstruction LowLevelILInstruction::GetRightExpr() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(RightExprLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw LowLevelILInstructionAccessException();
}


LowLevelILInstruction LowLevelILInstruction::GetCarryExpr() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(CarryExprLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw LowLevelILInstructionAccessException();
}


LowLevelILInstruction LowLevelILInstruction::GetConditionExpr() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(ConditionExprLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw LowLevelILInstructionAccessException();
}


uint32_t LowLevelILInstruction::GetHighRegister() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(HighRegisterLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsRegister(operandIndex);
	throw LowLevelILInstructionAccessException();
}


SSARegister LowLevelILInstruction::GetHighSSARegister() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(HighSSARegisterLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex).GetRawOperandAsSSARegister(LLILOperandIndex(0));
	throw LowLevelILInstructionAccessException();
}


uint32_t LowLevelILInstruction::GetLowRegister() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(LowRegisterLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsRegister(operandIndex);
	throw LowLevelILInstructionAccessException();
}


SSARegister LowLevelILInstruction::GetLowSSARegister() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(LowSSARegisterLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex).GetRawOperandAsSSARegister(LLILOperandIndex(0));
	throw LowLevelILInstructionAccessException();
}


uint32_t LowLevelILInstruction::GetIntrinsic() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(IntrinsicLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsRegister(operandIndex);
	throw LowLevelILInstructionAccessException();
}


int64_t LowLevelILInstruction::GetConstant() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(ConstantLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsInteger(operandIndex);
	throw LowLevelILInstructionAccessException();
}


uint64_t LowLevelILInstruction::GetOffset() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(OffsetLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsInteger(operandIndex);
	throw LowLevelILInstructionAccessException();
}


int64_t LowLevelILInstruction::GetVector() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(VectorLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsInteger(operandIndex);
	throw LowLevelILInstructionAccessException();
}


int64_t LowLevelILInstruction::GetStackAdjustment() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(StackAdjustmentLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsInteger(operandIndex);
	throw LowLevelILInstructionAccessException();
}


LLILLabelIndex LowLevelILInstruction::GetTarget() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(TargetLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsLabelIndex(operandIndex);
	throw LowLevelILInstructionAccessException();
}


LLILLabelIndex LowLevelILInstruction::GetTrueTarget() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(TrueTargetLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsLabelIndex(operandIndex);
	throw LowLevelILInstructionAccessException();
}


LLILLabelIndex LowLevelILInstruction::GetFalseTarget() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(FalseTargetLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsLabelIndex(operandIndex);
	throw LowLevelILInstructionAccessException();
}


size_t LowLevelILInstruction::GetBitIndex() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(BitIndexLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsIndex(operandIndex);
	throw LowLevelILInstructionAccessException();
}


size_t LowLevelILInstruction::GetSourceMemoryVersion() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(SourceMemoryVersionLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsIndex(operandIndex);
	if (GetOperandIndexForUsage(StackMemoryVersionLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex).GetRawOperandAsIndex(LLILOperandIndex(2));
	throw LowLevelILInstructionAccessException();
}


size_t LowLevelILInstruction::GetDestMemoryVersion() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(DestMemoryVersionLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsIndex(operandIndex);
	if (GetOperandIndexForUsage(OutputMemoryVersionLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex).GetRawOperandAsIndex(LLILOperandIndex(0));
	throw LowLevelILInstructionAccessException();
}


BNLowLevelILFlagCondition LowLevelILInstruction::GetFlagCondition() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(FlagConditionLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsFlagCondition(operandIndex);
	throw LowLevelILInstructionAccessException();
}


LowLevelILSSARegisterList LowLevelILInstruction::GetOutputSSARegisters() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(OutputSSARegistersLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex).GetRawOperandAsSSARegisterList(LLILOperandIndex(1));
	throw LowLevelILInstructionAccessException();
}


LowLevelILInstructionList LowLevelILInstruction::GetParameterExprs() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(ParameterExprsLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex).GetRawOperandAsExprList(LLILOperandIndex(0));
	throw LowLevelILInstructionAccessException();
}


LowLevelILSSARegisterList LowLevelILInstruction::GetSourceSSARegisters() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(SourceSSARegistersLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsSSARegisterList(operandIndex);
	throw LowLevelILInstructionAccessException();
}


LowLevelILSSARegisterStackList LowLevelILInstruction::GetSourceSSARegisterStacks() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(SourceSSARegisterStacksLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsSSARegisterStackList(operandIndex);
	throw LowLevelILInstructionAccessException();
}


LowLevelILSSAFlagList LowLevelILInstruction::GetSourceSSAFlags() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(SourceSSAFlagsLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsSSAFlagList(operandIndex);
	throw LowLevelILInstructionAccessException();
}


LowLevelILRegisterOrFlagList LowLevelILInstruction::GetOutputRegisterOrFlagList() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(OutputRegisterOrFlagListLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsRegisterOrFlagList(operandIndex);
	throw LowLevelILInstructionAccessException();
}


LowLevelILSSARegisterOrFlagList LowLevelILInstruction::GetOutputSSARegisterOrFlagList() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(OutputSSARegisterOrFlagListLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsSSARegisterOrFlagList(operandIndex);
	throw LowLevelILInstructionAccessException();
}


LowLevelILIndexList LowLevelILInstruction::GetSourceMemoryVersions() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(SourceMemoryVersionsLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsIndexList(operandIndex);
	throw LowLevelILInstructionAccessException();
}


LowLevelILIndexMap LowLevelILInstruction::GetTargets() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(TargetsLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsIndexMap(operandIndex);
	throw LowLevelILInstructionAccessException();
}


map<uint32_t, int32_t> LowLevelILInstruction::GetRegisterStackAdjustments() const
{
	LLILOperandIndex operandIndex;
	if (GetOperandIndexForUsage(RegisterStackAdjustmentsLowLevelOperandUsage, operandIndex))
		return GetRawOperandAsRegisterStackAdjustments(operandIndex);
	throw LowLevelILInstructionAccessException();
}


LLILExprId LowLevelILFunction::Nop(const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_NOP, loc, 0, 0);
}


LLILExprId LowLevelILFunction::SetRegister(
    size_t size, uint32_t reg, LLILExprId val, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SET_REG, loc, size, flags, LLILRawOperand::FromRegister(reg), LLILRawOperand::FromExprId(val));
}


LLILExprId LowLevelILFunction::SetRegisterSplit(
    size_t size, uint32_t high, uint32_t low, LLILExprId val, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SET_REG_SPLIT, loc, size, flags, LLILRawOperand::FromRegister(high), LLILRawOperand::FromRegister(low), LLILRawOperand::FromExprId(val));
}


LLILExprId LowLevelILFunction::SetRegisterSSA(size_t size, const SSARegister& reg, LLILExprId val, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SET_REG_SSA, loc, size, 0, LLILRawOperand::FromRegister(reg.reg), LLILRawOperand::FromVersion(reg.version), LLILRawOperand::FromExprId(val));
}


LLILExprId LowLevelILFunction::SetRegisterSSAPartial(
    size_t size, const SSARegister& fullReg, uint32_t partialReg, LLILExprId val, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SET_REG_SSA_PARTIAL, loc, size, 0, LLILRawOperand::FromRegister(fullReg.reg), LLILRawOperand::FromVersion(fullReg.version), LLILRawOperand::FromRegister(partialReg), LLILRawOperand::FromExprId(val));
}


LLILExprId LowLevelILFunction::SetRegisterSplitSSA(
    size_t size, const SSARegister& high, const SSARegister& low, LLILExprId val, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SET_REG_SPLIT_SSA, loc, size, 0,
	    LLILRawOperand::FromExprId(AddExprWithLocation(LLIL_REG_SPLIT_DEST_SSA, loc, size, 0, LLILRawOperand::FromRegister(high.reg), LLILRawOperand::FromVersion(high.version))),
	    LLILRawOperand::FromExprId(AddExprWithLocation(LLIL_REG_SPLIT_DEST_SSA, loc, size, 0, LLILRawOperand::FromRegister(low.reg), LLILRawOperand::FromVersion(low.version), LLILRawOperand::FromExprId(val))));
}


LLILExprId LowLevelILFunction::SetRegisterStackTopRelative(
    size_t size, uint32_t regStack, LLILExprId entry, LLILExprId val, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SET_REG_STACK_REL, loc, size, flags, LLILRawOperand::FromRegisterStack(regStack), LLILRawOperand::FromExprId(entry), LLILRawOperand::FromExprId(val));
}


LLILExprId LowLevelILFunction::RegisterStackPush(
    size_t size, uint32_t regStack, LLILExprId val, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_STACK_PUSH, loc, size, flags, LLILRawOperand::FromRegisterStack(regStack), LLILRawOperand::FromExprId(val));
}


LLILExprId LowLevelILFunction::SetRegisterStackTopRelativeSSA(size_t size, uint32_t regStack, size_t destVersion,
    size_t srcVersion, LLILExprId entry, const SSARegister& top, LLILExprId val, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SET_REG_STACK_REL_SSA, loc, size, 0,
	    LLILRawOperand::FromExprId(AddExprWithLocation(LLIL_REG_STACK_DEST_SSA, loc, size, 0, LLILRawOperand::FromRegisterStack(regStack), LLILRawOperand::FromVersion(destVersion), LLILRawOperand::FromVersion(srcVersion))), LLILRawOperand::FromExprId(entry),
	    LLILRawOperand::FromExprId(AddExprWithLocation(LLIL_REG_SSA, loc, 0, 0, LLILRawOperand::FromRegister(top.reg), LLILRawOperand::FromVersion(top.version))), LLILRawOperand::FromExprId(val));
}


LLILExprId LowLevelILFunction::SetRegisterStackAbsoluteSSA(size_t size, uint32_t regStack, size_t destVersion,
    size_t srcVersion, uint32_t reg, LLILExprId val, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SET_REG_STACK_ABS_SSA, loc, size, 0,
		LLILRawOperand::FromExprId(AddExprWithLocation(LLIL_REG_STACK_DEST_SSA, loc, size, 0, LLILRawOperand::FromRegisterStack(regStack), LLILRawOperand::FromVersion(destVersion), LLILRawOperand::FromVersion(srcVersion))), LLILRawOperand::FromRegister(reg), LLILRawOperand::FromExprId(val));
}


LLILExprId LowLevelILFunction::SetFlag(uint32_t flag, LLILExprId val, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SET_FLAG, loc, 0, 0, LLILRawOperand::FromFlag(flag), LLILRawOperand::FromExprId(val));
}


LLILExprId LowLevelILFunction::SetFlagSSA(const SSAFlag& flag, LLILExprId val, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SET_FLAG_SSA, loc, 0, 0, LLILRawOperand::FromFlag(flag.flag), LLILRawOperand::FromVersion(flag.version), LLILRawOperand::FromExprId(val));
}


LLILExprId LowLevelILFunction::Load(size_t size, LLILExprId addr, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_LOAD, loc, size, flags, LLILRawOperand::FromExprId(addr));
}


LLILExprId LowLevelILFunction::LoadSSA(size_t size, LLILExprId addr, size_t sourceMemoryVer, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_LOAD_SSA, loc, size, 0, LLILRawOperand::FromExprId(addr), LLILRawOperand::FromVersion(sourceMemoryVer));
}


LLILExprId LowLevelILFunction::Store(size_t size, LLILExprId addr, LLILExprId val, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_STORE, loc, size, flags, LLILRawOperand::FromExprId(addr), LLILRawOperand::FromExprId(val));
}


LLILExprId LowLevelILFunction::StoreSSA(
    size_t size, LLILExprId addr, LLILExprId val, size_t newMemoryVer, size_t prevMemoryVer, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_STORE_SSA, loc, size, 0, LLILRawOperand::FromExprId(addr), LLILRawOperand::FromVersion(newMemoryVer), LLILRawOperand::FromVersion(prevMemoryVer), LLILRawOperand::FromExprId(val));
}


LLILExprId LowLevelILFunction::Push(size_t size, LLILExprId val, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_PUSH, loc, size, flags, LLILRawOperand::FromExprId(val));
}


LLILExprId LowLevelILFunction::Pop(size_t size, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_POP, loc, size, flags);
}


LLILExprId LowLevelILFunction::Register(size_t size, uint32_t reg, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG, loc, size, 0, LLILRawOperand::FromRegister(reg));
}


LLILExprId LowLevelILFunction::RegisterSSA(size_t size, const SSARegister& reg, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_SSA, loc, size, 0, LLILRawOperand::FromRegister(reg.reg), LLILRawOperand::FromVersion(reg.version));
}


LLILExprId LowLevelILFunction::RegisterSSAPartial(
    size_t size, const SSARegister& fullReg, uint32_t partialReg, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_SSA_PARTIAL, loc, size, 0, LLILRawOperand::FromRegister(fullReg.reg), LLILRawOperand::FromVersion(fullReg.version), LLILRawOperand::FromRegister(partialReg));
}


LLILExprId LowLevelILFunction::RegisterSplit(size_t size, uint32_t high, uint32_t low, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_SPLIT, loc, size, 0, LLILRawOperand::FromRegister(high), LLILRawOperand::FromRegister(low));
}


LLILExprId LowLevelILFunction::RegisterSplitSSA(
    size_t size, const SSARegister& high, const SSARegister& low, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_SPLIT_SSA, loc, size, 0, LLILRawOperand::FromRegister(high.reg), LLILRawOperand::FromVersion(high.version), LLILRawOperand::FromRegister(low.reg), LLILRawOperand::FromVersion(low.version));
}


LLILExprId LowLevelILFunction::RegisterStackTopRelative(
    size_t size, uint32_t regStack, LLILExprId entry, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_STACK_REL, loc, size, 0, LLILRawOperand::FromRegisterStack(regStack), LLILRawOperand::FromExprId(entry));
}


LLILExprId LowLevelILFunction::RegisterStackPop(size_t size, uint32_t regStack, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_STACK_POP, loc, size, flags, LLILRawOperand::FromRegisterStack(regStack));
}


LLILExprId LowLevelILFunction::RegisterStackFreeReg(uint32_t reg, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_STACK_FREE_REG, loc, 0, 0, LLILRawOperand::FromRegister(reg));
}


LLILExprId LowLevelILFunction::RegisterStackFreeTopRelative(uint32_t regStack, LLILExprId entry, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_STACK_FREE_REG, loc, 0, 0, LLILRawOperand::FromRegisterStack(regStack), LLILRawOperand::FromExprId(entry));
}


LLILExprId LowLevelILFunction::RegisterStackTopRelativeSSA(
    size_t size, const SSARegisterStack& regStack, LLILExprId entry, const SSARegister& top, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_STACK_REL_SSA, loc, size, 0, LLILRawOperand::FromRegisterStack(regStack.regStack), LLILRawOperand::FromVersion(regStack.version), LLILRawOperand::FromExprId(entry),
	    LLILRawOperand::FromExprId(AddExprWithLocation(LLIL_REG_SSA, loc, 0, 0, LLILRawOperand::FromRegister(top.reg), LLILRawOperand::FromVersion(top.version))));
}


LLILExprId LowLevelILFunction::RegisterStackAbsoluteSSA(
    size_t size, const SSARegisterStack& regStack, uint32_t reg, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_STACK_ABS_SSA, loc, size, 0, LLILRawOperand::FromRegisterStack(regStack.regStack), LLILRawOperand::FromVersion(regStack.version), LLILRawOperand::FromRegister(reg));
}


LLILExprId LowLevelILFunction::RegisterStackFreeTopRelativeSSA(uint32_t regStack, size_t destVersion, size_t srcVersion,
    LLILExprId entry, const SSARegister& top, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_STACK_FREE_REL_SSA, loc, 0, 0,
	    LLILRawOperand::FromExprId(AddExprWithLocation(LLIL_REG_STACK_DEST_SSA, loc, 0, 0, LLILRawOperand::FromRegisterStack(regStack), LLILRawOperand::FromVersion(destVersion), LLILRawOperand::FromVersion(srcVersion))), LLILRawOperand::FromExprId(entry),
	    LLILRawOperand::FromExprId(AddExprWithLocation(LLIL_REG_SSA, loc, 0, 0, LLILRawOperand::FromRegister(top.reg), LLILRawOperand::FromVersion(top.version))));
}


LLILExprId LowLevelILFunction::RegisterStackFreeAbsoluteSSA(
    uint32_t regStack, size_t destVersion, size_t srcVersion, uint32_t reg, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_STACK_FREE_ABS_SSA, loc, 0, 0,
		LLILRawOperand::FromExprId(AddExprWithLocation(LLIL_REG_STACK_DEST_SSA, loc, 0, 0, LLILRawOperand::FromRegisterStack(regStack), LLILRawOperand::FromVersion(destVersion), LLILRawOperand::FromVersion(srcVersion))), LLILRawOperand::FromRegister(reg));
}


LLILExprId LowLevelILFunction::Const(size_t size, uint64_t val, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CONST, loc, size, 0, LLILRawOperand::FromConstant(LLILConstantInt(val)));
}


LLILExprId LowLevelILFunction::ConstPointer(size_t size, uint64_t val, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CONST_PTR, loc, size, 0, LLILRawOperand::FromConstant(LLILConstantInt(val)));
}


LLILExprId LowLevelILFunction::ExternPointer(size_t size, uint64_t val, uint64_t offset, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_EXTERN_PTR, loc, size, 0, LLILRawOperand::FromConstant(LLILConstantInt(val)), LLILRawOperand::FromConstant(LLILConstantInt(val)));
}


LLILExprId LowLevelILFunction::FloatConstRaw(size_t size, uint64_t val, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FLOAT_CONST, loc, size, 0, LLILRawOperand::FromConstant(LLILConstantInt(val)));
}


LLILExprId LowLevelILFunction::FloatConstSingle(float val, const ILSourceLocation& loc)
{
	union
	{
		float f;
		uint32_t i;
	} bits;
	bits.f = val;
	return AddExprWithLocation(LLIL_FLOAT_CONST, loc, 4, 0, LLILRawOperand::FromConstant(LLILConstantInt(bits.i)));
}


LLILExprId LowLevelILFunction::FloatConstDouble(double val, const ILSourceLocation& loc)
{
	union
	{
		double f;
		uint64_t i;
	} bits;
	bits.f = val;
	return AddExprWithLocation(LLIL_FLOAT_CONST, loc, 8, 0, LLILRawOperand::FromConstant(LLILConstantInt(bits.i)));
}


LLILExprId LowLevelILFunction::Flag(uint32_t flag, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FLAG, loc, 0, 0, LLILRawOperand::FromFlag(flag));
}


LLILExprId LowLevelILFunction::FlagSSA(const SSAFlag& flag, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FLAG_SSA, loc, 0, 0, LLILRawOperand::FromFlag(flag.flag), LLILRawOperand::FromVersion(flag.version));
}


LLILExprId LowLevelILFunction::FlagBit(size_t size, uint32_t flag, size_t bitIndex, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FLAG_BIT, loc, size, 0, LLILRawOperand::FromFlag(flag), LLILRawOperand::FromIndex(bitIndex));
}


LLILExprId LowLevelILFunction::FlagBitSSA(size_t size, const SSAFlag& flag, size_t bitIndex, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FLAG_BIT_SSA, loc, size, 0, LLILRawOperand::FromFlag(flag.flag), LLILRawOperand::FromVersion(flag.version), LLILRawOperand::FromIndex(bitIndex));
}


LLILExprId LowLevelILFunction::Add(size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_ADD, loc, size, flags, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::AddCarry(
    size_t size, LLILExprId a, LLILExprId b, LLILExprId carry, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_ADC, loc, size, flags, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b), LLILRawOperand::FromExprId(carry));
}


LLILExprId LowLevelILFunction::Sub(size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SUB, loc, size, flags, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::SubBorrow(
    size_t size, LLILExprId a, LLILExprId b, LLILExprId carry, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SBB, loc, size, flags, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b), LLILRawOperand::FromExprId(carry));
}


LLILExprId LowLevelILFunction::And(size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_AND, loc, size, flags, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::Or(size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_OR, loc, size, flags, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::Xor(size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_XOR, loc, size, flags, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::ShiftLeft(size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_LSL, loc, size, flags, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::LogicalShiftRight(
    size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_LSR, loc, size, flags, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::ArithShiftRight(size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_ASR, loc, size, flags, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::RotateLeft(size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_ROL, loc, size, flags, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::RotateLeftCarry(
    size_t size, LLILExprId a, LLILExprId b, LLILExprId carry, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_RLC, loc, size, flags, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b), LLILRawOperand::FromExprId(carry));
}


LLILExprId LowLevelILFunction::RotateRight(size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_ROR, loc, size, flags, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::RotateRightCarry(
    size_t size, LLILExprId a, LLILExprId b, LLILExprId carry, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_RRC, loc, size, flags, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b), LLILRawOperand::FromExprId(carry));
}


LLILExprId LowLevelILFunction::Mult(size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_MUL, loc, size, flags, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::MultDoublePrecUnsigned(
    size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_MULU_DP, loc, size, flags, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::MultDoublePrecSigned(
    size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_MULS_DP, loc, size, flags, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::DivUnsigned(size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_DIVU, loc, size, flags, LLILRawOperand::FromExprId(a),LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::DivDoublePrecUnsigned(
    size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_DIVU_DP, loc, size, flags, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::DivSigned(size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_DIVS, loc, size, flags, LLILRawOperand::FromExprId(a),LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::DivDoublePrecSigned(
    size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_DIVS_DP, loc, size, flags, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::ModUnsigned(size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_MODU, loc, size, flags, LLILRawOperand::FromExprId(a),LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::ModDoublePrecUnsigned(
    size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_MODU_DP, loc, size, flags, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::ModSigned(size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_MODS, loc, size, flags, LLILRawOperand::FromExprId(a),LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::ModDoublePrecSigned(
    size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_MODS_DP, loc, size, flags, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::Neg(size_t size, LLILExprId a, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_NEG, loc, size, flags, LLILRawOperand::FromExprId(a));
}


LLILExprId LowLevelILFunction::Not(size_t size, LLILExprId a, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_NOT, loc, size, flags, LLILRawOperand::FromExprId(a));
}


LLILExprId LowLevelILFunction::SignExtend(size_t size, LLILExprId a, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SX, loc, size, flags, LLILRawOperand::FromExprId(a));
}


LLILExprId LowLevelILFunction::ZeroExtend(size_t size, LLILExprId a, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_ZX, loc, size, flags, LLILRawOperand::FromExprId(a));
}


LLILExprId LowLevelILFunction::LowPart(size_t size, LLILExprId a, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_LOW_PART, loc, size, flags, LLILRawOperand::FromExprId(a));
}


LLILExprId LowLevelILFunction::Jump(LLILExprId dest, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_JUMP, loc, 0, 0, LLILRawOperand::FromExprId(dest));
}


LLILExprId LowLevelILFunction::JumpTo(
    LLILExprId dest, const map<uint64_t, BNLowLevelILLabel*>& targets, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_JUMP_TO, loc, 0, 0, LLILRawOperand::FromExprId(dest), LLILRawOperand::FromCount(targets.size() * 2), LLILRawOperand::FromExprId(AddLabelMap(targets)));
}


LLILExprId LowLevelILFunction::Call(LLILExprId dest, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CALL, loc, 0, 0, LLILRawOperand::FromExprId(dest));
}


LLILExprId LowLevelILFunction::CallStackAdjust(
    LLILExprId dest, int64_t adjust, const map<uint32_t, int32_t>& regStackAdjust, const ILSourceLocation& loc)
{
	vector<size_t> list;
	for (auto& i : regStackAdjust)
	{
		list.push_back(i.first);
		list.push_back(i.second);
	}
	return AddExprWithLocation(LLIL_CALL_STACK_ADJUST, loc, 0, 0, LLILRawOperand::FromExprId(dest), LLILRawOperand::FromAdjustment(adjust), LLILRawOperand::FromCount(list.size()), LLILRawOperand::FromExprId(AddIndexList(list)));
}


LLILExprId LowLevelILFunction::TailCall(LLILExprId dest, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_TAILCALL, loc, 0, 0, LLILRawOperand::FromExprId(dest));
}


LLILExprId LowLevelILFunction::CallSSA(const vector<SSARegister>& output, LLILExprId dest, const vector<LLILExprId>& params,
    const SSARegister& stack, size_t newMemoryVer, size_t prevMemoryVer, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CALL_SSA, loc, 0, 0,
	    AddExprWithLocation(
	        LLIL_CALL_OUTPUT_SSA, loc, 0, 0, newMemoryVer, output.size() * 2, AddSSARegisterList(output)),
	    dest, AddExprWithLocation(LLIL_CALL_STACK_SSA, loc, 0, 0, stack.reg, stack.version, prevMemoryVer),
	    AddExprWithLocation(LLIL_CALL_PARAM, loc, 0, 0, params.size(), AddOperandList(params)));
}


LLILExprId LowLevelILFunction::SystemCallSSA(const vector<SSARegister>& output, const vector<LLILExprId>& params,
    const SSARegister& stack, size_t newMemoryVer, size_t prevMemoryVer, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SYSCALL_SSA, loc, 0, 0,
	    AddExprWithLocation(
	        LLIL_CALL_OUTPUT_SSA, loc, 0, 0, newMemoryVer, output.size() * 2, AddSSARegisterList(output)),
	    AddExprWithLocation(LLIL_CALL_STACK_SSA, loc, 0, 0, stack.reg, stack.version, prevMemoryVer),
	    AddExprWithLocation(LLIL_CALL_PARAM, loc, 0, 0, params.size(), AddOperandList(params)));
}


LLILExprId LowLevelILFunction::TailCallSSA(const vector<SSARegister>& output, LLILExprId dest, const vector<LLILExprId>& params,
    const SSARegister& stack, size_t newMemoryVer, size_t prevMemoryVer, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_TAILCALL_SSA, loc, 0, 0,
	    AddExprWithLocation(
	        LLIL_CALL_OUTPUT_SSA, loc, 0, 0, newMemoryVer, output.size() * 2, AddSSARegisterList(output)),
	    dest, AddExprWithLocation(LLIL_CALL_STACK_SSA, loc, 0, 0, stack.reg, stack.version, prevMemoryVer),
	    AddExprWithLocation(LLIL_CALL_PARAM, loc, 0, 0, params.size(), AddOperandList(params)));
}


LLILExprId LowLevelILFunction::Return(LLILExprId dest, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_RET, loc, 0, 0, LLILRawOperand::FromExprId(dest));
}


LLILExprId LowLevelILFunction::NoReturn(const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_NORET, loc, 0, 0);
}


LLILExprId LowLevelILFunction::FlagCondition(BNLowLevelILFlagCondition cond, uint32_t semClass, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FLAG_COND, loc, 0, 0, LLILRawOperand::FromFlagCondition(cond), LLILRawOperand::FromSemanticClass(semClass));
}


LLILExprId LowLevelILFunction::FlagGroup(uint32_t semGroup, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FLAG_GROUP, loc, 0, 0, LLILRawOperand::FromSemanticGroup(semGroup));
}


LLILExprId LowLevelILFunction::CompareEqual(size_t size, LLILExprId a, LLILExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CMP_E, loc, size, 0, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::CompareNotEqual(size_t size, LLILExprId a, LLILExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CMP_NE, loc, size, 0, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::CompareSignedLessThan(size_t size, LLILExprId a, LLILExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CMP_SLT, loc, size, 0, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::CompareUnsignedLessThan(size_t size, LLILExprId a, LLILExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CMP_ULT, loc, size, 0, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::CompareSignedLessEqual(size_t size, LLILExprId a, LLILExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CMP_SLE, loc, size, 0, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::CompareUnsignedLessEqual(size_t size, LLILExprId a, LLILExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CMP_ULE, loc, size, 0, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::CompareSignedGreaterEqual(size_t size, LLILExprId a, LLILExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CMP_SGE, loc, size, 0, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::CompareUnsignedGreaterEqual(size_t size, LLILExprId a, LLILExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CMP_UGE, loc, size, 0, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::CompareSignedGreaterThan(size_t size, LLILExprId a, LLILExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CMP_SGT, loc, size, 0, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::CompareUnsignedGreaterThan(size_t size, LLILExprId a, LLILExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CMP_UGT, loc, size, 0, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::TestBit(size_t size, LLILExprId a, LLILExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_TEST_BIT, loc, size, 0, LLILRawOperand::FromExprId(a),LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::BoolToInt(size_t size, LLILExprId a, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_BOOL_TO_INT, loc, size, 0, LLILRawOperand::FromExprId(a));
}


LLILExprId LowLevelILFunction::SystemCall(const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SYSCALL, loc, 0, 0);
}


LLILExprId LowLevelILFunction::Intrinsic(const vector<RegisterOrFlag>& outputs, uint32_t intrinsic,
    const vector<LLILExprId>& params, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_INTRINSIC, loc, 0, flags, outputs.size(), LLILRawOperand::FromExprId(AddRegisterOrFlagList(outputs)), intrinsic,
	    AddExprWithLocation(LLIL_CALL_PARAM, loc, 0, 0, params.size(), LLILRawOperand::FromExprId(AddOperandList(params))));
}


LLILExprId LowLevelILFunction::IntrinsicSSA(const vector<SSARegisterOrFlag>& outputs, uint32_t intrinsic,
    const vector<LLILExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_INTRINSIC_SSA, loc, 0, 0, outputs.size() * 2, LLILRawOperand::FromExprId(AddSSARegisterOrFlagList(outputs)),
	    intrinsic, AddExprWithLocation(LLIL_CALL_PARAM, loc, 0, 0, params.size(), LLILRawOperand::FromExprId(AddOperandList(params))));
}


LLILExprId LowLevelILFunction::Breakpoint(const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_BP, loc, 0, 0);
}


LLILExprId LowLevelILFunction::Trap(int64_t num, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_TRAP, loc, 0, 0, num);
}


LLILExprId LowLevelILFunction::Undefined(const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_UNDEF, loc, 0, 0);
}


LLILExprId LowLevelILFunction::Unimplemented(const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_UNIMPL, loc, 0, 0);
}


LLILExprId LowLevelILFunction::UnimplementedMemoryRef(size_t size, LLILExprId addr, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_UNIMPL_MEM, loc, size, 0, addr);
}


LLILExprId LowLevelILFunction::RegisterPhi(
    const SSARegister& dest, const vector<SSARegister>& sources, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    LLIL_REG_PHI, loc, 0, 0, dest.reg, dest.version, sources.size() * 2, AddSSARegisterList(sources));
}


LLILExprId LowLevelILFunction::RegisterStackPhi(
    const SSARegisterStack& dest, const vector<SSARegisterStack>& sources, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_STACK_PHI, loc, 0, 0, dest.regStack, dest.version, sources.size() * 2,
	    AddSSARegisterStackList(sources));
}


LLILExprId LowLevelILFunction::FlagPhi(const SSAFlag& dest, const vector<SSAFlag>& sources, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    LLIL_FLAG_PHI, loc, 0, 0, dest.flag, dest.version, sources.size() * 2, AddSSAFlagList(sources));
}


LLILExprId LowLevelILFunction::MemoryPhi(size_t dest, const vector<size_t>& sources, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_MEM_PHI, loc, 0, 0, dest, sources.size(), AddIndexList(sources));
}


LLILExprId LowLevelILFunction::FloatAdd(size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FADD, loc, size, flags, LLILRawOperand::FromExprId(a),LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::FloatSub(size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FSUB, loc, size, flags, LLILRawOperand::FromExprId(a),LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::FloatMult(size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FMUL, loc, size, flags, LLILRawOperand::FromExprId(a),LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::FloatDiv(size_t size, LLILExprId a, LLILExprId b, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FDIV, loc, size, flags, LLILRawOperand::FromExprId(a),LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::FloatSqrt(size_t size, LLILExprId a, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FSQRT, loc, size, flags, LLILRawOperand::FromExprId(a));
}


LLILExprId LowLevelILFunction::FloatNeg(size_t size, LLILExprId a, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FNEG, loc, size, flags, LLILRawOperand::FromExprId(a));
}


LLILExprId LowLevelILFunction::FloatAbs(size_t size, LLILExprId a, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FABS, loc, size, flags, LLILRawOperand::FromExprId(a));
}


LLILExprId LowLevelILFunction::FloatToInt(size_t size, LLILExprId a, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FLOAT_TO_INT, loc, size, flags, LLILRawOperand::FromExprId(a));
}


LLILExprId LowLevelILFunction::IntToFloat(size_t size, LLILExprId a, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_INT_TO_FLOAT, loc, size, flags, LLILRawOperand::FromExprId(a));
}


LLILExprId LowLevelILFunction::FloatConvert(size_t size, LLILExprId a, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FLOAT_CONV, loc, size, flags, LLILRawOperand::FromExprId(a));
}


LLILExprId LowLevelILFunction::RoundToInt(size_t size, LLILExprId a, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_ROUND_TO_INT, loc, size, flags, LLILRawOperand::FromExprId(a));
}


LLILExprId LowLevelILFunction::Floor(size_t size, LLILExprId a, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FLOOR, loc, size, flags, LLILRawOperand::FromExprId(a));
}


LLILExprId LowLevelILFunction::Ceil(size_t size, LLILExprId a, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CEIL, loc, size, flags, LLILRawOperand::FromExprId(a));
}


LLILExprId LowLevelILFunction::FloatTrunc(size_t size, LLILExprId a, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FTRUNC, loc, size, flags, LLILRawOperand::FromExprId(a));
}


LLILExprId LowLevelILFunction::FloatCompareEqual(size_t size, LLILExprId a, LLILExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FCMP_E, loc, size, 0, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::FloatCompareNotEqual(size_t size, LLILExprId a, LLILExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FCMP_NE, loc, size, 0, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::FloatCompareLessThan(size_t size, LLILExprId a, LLILExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FCMP_LT, loc, size, 0, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::FloatCompareLessEqual(size_t size, LLILExprId a, LLILExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FCMP_LE, loc, size, 0, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::FloatCompareGreaterEqual(size_t size, LLILExprId a, LLILExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FCMP_GE, loc, size, 0, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::FloatCompareGreaterThan(size_t size, LLILExprId a, LLILExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FCMP_GT, loc, size, 0, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::FloatCompareOrdered(size_t size, LLILExprId a, LLILExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FCMP_O, loc, size, 0, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}


LLILExprId LowLevelILFunction::FloatCompareUnordered(size_t size, LLILExprId a, LLILExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FCMP_UO, loc, size, 0, LLILRawOperand::FromExprId(a), LLILRawOperand::FromExprId(b));
}
