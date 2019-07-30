// Copyright (c) 2019 Vector 35 Inc
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
#include "highlevelilfunction.h"
#include "mediumlevelilfunction.h"
#include "mediumlevelilssafunction.h"
using namespace BinaryNinjaCore;
#else
#include "binaryninjaapi.h"
#include "highlevelilinstruction.h"
#include "mediumlevelilinstruction.h"
using namespace BinaryNinja;
#endif

using namespace std;


unordered_map<HighLevelILOperandUsage, HighLevelILOperandType>
	HighLevelILInstructionBase::operandTypeForUsage = {
		{SourceExprHighLevelOperandUsage, ExprHighLevelOperand},
		{VariableHighLevelOperandUsage, VariableHighLevelOperand},
		{SSAVariableHighLevelOperandUsage, SSAVariableHighLevelOperand},
		{DestSSAVariableHighLevelOperandUsage, SSAVariableHighLevelOperand},
		{DestExprHighLevelOperandUsage, ExprHighLevelOperand},
		{LeftExprHighLevelOperandUsage, ExprHighLevelOperand},
		{RightExprHighLevelOperandUsage, ExprHighLevelOperand},
		{CarryExprHighLevelOperandUsage, ExprHighLevelOperand},
		{IndexExprHighLevelOperandUsage, ExprHighLevelOperand},
		{ConditionExprHighLevelOperandUsage, ExprHighLevelOperand},
		{TrueExprHighLevelOperandUsage, ExprHighLevelOperand},
		{FalseExprHighLevelOperandUsage, ExprHighLevelOperand},
		{LoopExprHighLevelOperandUsage, ExprHighLevelOperand},
		{InitExprHighLevelOperandUsage, ExprHighLevelOperand},
		{UpdateExprHighLevelOperandUsage, ExprHighLevelOperand},
		{DefaultExprHighLevelOperandUsage, ExprHighLevelOperand},
		{HighExprHighLevelOperandUsage, ExprHighLevelOperand},
		{LowExprHighLevelOperandUsage, ExprHighLevelOperand},
		{OffsetHighLevelOperandUsage, IntegerHighLevelOperand},
		{ConstantHighLevelOperandUsage, IntegerHighLevelOperand},
		{VectorHighLevelOperandUsage, IntegerHighLevelOperand},
		{IntrinsicHighLevelOperandUsage, IntrinsicHighLevelOperand},
		{TargetHighLevelOperandUsage, IndexHighLevelOperand},
		{ParameterExprsHighLevelOperandUsage, ExprListHighLevelOperand},
		{SourceExprsHighLevelOperandUsage, ExprListHighLevelOperand},
		{DestExprsHighLevelOperandUsage, ExprListHighLevelOperand},
		{BlockExprsHighLevelOperandUsage, ExprListHighLevelOperand},
		{CasesHighLevelOperandUsage, ExprListHighLevelOperand},
		{SourceSSAVariablesHighLevelOperandUsage, SSAVariableListHighLevelOperand}
	};


unordered_map<BNHighLevelILOperation, vector<HighLevelILOperandUsage>>
	HighLevelILInstructionBase::operationOperandUsage = {
		{HLIL_NOP, {}},
		{HLIL_BREAK, {}},
		{HLIL_CONTINUE, {}},
		{HLIL_NORET, {}},
		{HLIL_BP, {}},
		{HLIL_UNDEF, {}},
		{HLIL_UNIMPL, {}},
		{HLIL_BLOCK, {BlockExprsHighLevelOperandUsage}},
		{HLIL_IF, {ConditionExprHighLevelOperandUsage, TrueExprHighLevelOperandUsage,
			FalseExprHighLevelOperandUsage}},
		{HLIL_WHILE, {ConditionExprHighLevelOperandUsage, LoopExprHighLevelOperandUsage}},
		{HLIL_DO_WHILE, {LoopExprHighLevelOperandUsage, ConditionExprHighLevelOperandUsage}},
		{HLIL_FOR, {InitExprHighLevelOperandUsage, ConditionExprHighLevelOperandUsage,
			UpdateExprHighLevelOperandUsage, LoopExprHighLevelOperandUsage}},
		{HLIL_SWITCH, {ConditionExprHighLevelOperandUsage, DefaultExprHighLevelOperandUsage,
			CasesHighLevelOperandUsage}},
		{HLIL_CASE, {ConditionExprHighLevelOperandUsage, TrueExprHighLevelOperandUsage}},
		{HLIL_JUMP, {DestExprHighLevelOperandUsage}},
		{HLIL_RET, {SourceExprsHighLevelOperandUsage}},
		{HLIL_GOTO, {TargetHighLevelOperandUsage}},
		{HLIL_LABEL, {TargetHighLevelOperandUsage}},
		{HLIL_ASSIGN, {DestExprHighLevelOperandUsage, SourceExprHighLevelOperandUsage}},
		{HLIL_ASSIGN_UNPACK, {DestExprsHighLevelOperandUsage, SourceExprHighLevelOperandUsage}},
		{HLIL_VAR, {VariableHighLevelOperandUsage}},
		{HLIL_VAR_SSA, {SSAVariableHighLevelOperandUsage}},
		{HLIL_VAR_PHI, {DestSSAVariableHighLevelOperandUsage, SourceSSAVariablesHighLevelOperandUsage}},
		{HLIL_STRUCT_FIELD, {SourceExprHighLevelOperandUsage, OffsetHighLevelOperandUsage}},
		{HLIL_ARRAY_INDEX, {SourceExprHighLevelOperandUsage, IndexExprHighLevelOperandUsage}},
		{HLIL_SPLIT, {HighExprHighLevelOperandUsage, LowExprHighLevelOperandUsage}},
		{HLIL_DEREF, {SourceExprHighLevelOperandUsage}},
		{HLIL_DEREF_FIELD, {SourceExprHighLevelOperandUsage, OffsetHighLevelOperandUsage}},
		{HLIL_ADDRESS_OF, {SourceExprHighLevelOperandUsage}},
		{HLIL_CALL, {DestExprHighLevelOperandUsage, ParameterExprsHighLevelOperandUsage}},
		{HLIL_SYSCALL, {ParameterExprsHighLevelOperandUsage}},
		{HLIL_TAILCALL, {DestExprHighLevelOperandUsage, ParameterExprsHighLevelOperandUsage}},
		{HLIL_INTRINSIC, {IntrinsicHighLevelOperandUsage, ParameterExprsHighLevelOperandUsage}},
		{HLIL_TRAP, {VectorHighLevelOperandUsage}},
		{HLIL_CONST, {ConstantHighLevelOperandUsage}},
		{HLIL_CONST_PTR, {ConstantHighLevelOperandUsage}},
		{HLIL_EXTERN_PTR, {ConstantHighLevelOperandUsage, OffsetHighLevelOperandUsage}},
		{HLIL_FLOAT_CONST, {ConstantHighLevelOperandUsage}},
		{HLIL_IMPORT, {ConstantHighLevelOperandUsage}},
		{HLIL_ADD, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_SUB, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_AND, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_OR, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_XOR, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_LSL, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_LSR, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_ASR, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_ROL, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_ROR, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_MUL, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_MULU_DP, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_MULS_DP, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_DIVU, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_DIVS, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_MODU, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_MODS, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_CMP_E, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_CMP_NE, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_CMP_SLT, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_CMP_ULT, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_CMP_SLE, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_CMP_ULE, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_CMP_SGE, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_CMP_UGE, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_CMP_SGT, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_CMP_UGT, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_TEST_BIT, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_ADD_OVERFLOW, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_ADC, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage,
			CarryExprHighLevelOperandUsage}},
		{HLIL_SBB, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage,
			CarryExprHighLevelOperandUsage}},
		{HLIL_RLC, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage,
			CarryExprHighLevelOperandUsage}},
		{HLIL_RRC, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage,
			CarryExprHighLevelOperandUsage}},
		{HLIL_DIVU_DP, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_DIVS_DP, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_MODU_DP, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_MODS_DP, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_NEG, {SourceExprHighLevelOperandUsage}},
		{HLIL_NOT, {SourceExprHighLevelOperandUsage}},
		{HLIL_SX, {SourceExprHighLevelOperandUsage}},
		{HLIL_ZX, {SourceExprHighLevelOperandUsage}},
		{HLIL_LOW_PART, {SourceExprHighLevelOperandUsage}},
		{HLIL_BOOL_TO_INT, {SourceExprHighLevelOperandUsage}},
		{HLIL_UNIMPL_MEM, {SourceExprHighLevelOperandUsage}},
		{HLIL_FADD, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_FSUB, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_FMUL, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_FDIV, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_FSQRT, {SourceExprHighLevelOperandUsage}},
		{HLIL_FNEG, {SourceExprHighLevelOperandUsage}},
		{HLIL_FABS, {SourceExprHighLevelOperandUsage}},
		{HLIL_FLOAT_TO_INT, {SourceExprHighLevelOperandUsage}},
		{HLIL_INT_TO_FLOAT, {SourceExprHighLevelOperandUsage}},
		{HLIL_FLOAT_CONV, {SourceExprHighLevelOperandUsage}},
		{HLIL_ROUND_TO_INT, {SourceExprHighLevelOperandUsage}},
		{HLIL_FLOOR, {SourceExprHighLevelOperandUsage}},
		{HLIL_CEIL, {SourceExprHighLevelOperandUsage}},
		{HLIL_FTRUNC, {SourceExprHighLevelOperandUsage}},
		{HLIL_FCMP_E, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_FCMP_NE, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_FCMP_LT, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_FCMP_LE, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_FCMP_GE, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_FCMP_GT, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_FCMP_O, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
		{HLIL_FCMP_UO, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}}
	};


static unordered_map<BNHighLevelILOperation, unordered_map<HighLevelILOperandUsage, size_t>> GetOperandIndexForOperandUsages()
{
	unordered_map<BNHighLevelILOperation, unordered_map<HighLevelILOperandUsage, size_t>> result;
	result.reserve(HighLevelILInstructionBase::operationOperandUsage.size());
	for (auto& operation : HighLevelILInstructionBase::operationOperandUsage)
	{
		result[operation.first] = unordered_map<HighLevelILOperandUsage, size_t>();
		result[operation.first].reserve(operation.second.size());
		size_t operand = 0;
		for (auto usage : operation.second)
		{
			result[operation.first][usage] = operand;
			switch (HighLevelILInstructionBase::operandTypeForUsage[usage])
			{
			case SSAVariableHighLevelOperand:
			case SSAVariableListHighLevelOperand:
			case ExprListHighLevelOperand:
				// SSA variables and lists take two operand slots
				operand += 2;
				break;
			default:
				operand++;
				break;
			}
		}
	}
	return result;
}


unordered_map<BNHighLevelILOperation, unordered_map<HighLevelILOperandUsage, size_t>>
	HighLevelILInstructionBase::operationOperandIndex = GetOperandIndexForOperandUsages();


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
	if (count == 0)
		return *this;

	operand++;
	if (operand >= 4)
	{
		operand = 0;
		instr = function->GetRawExpr((size_t)instr.operands[4]);
	}
	return *this;
}


uint64_t HighLevelILIntegerList::ListIterator::operator*()
{
	return instr.operands[operand];
}


HighLevelILIntegerList::HighLevelILIntegerList(HighLevelILFunction* func,
	const BNHighLevelILInstruction& instr, size_t count)
{
	m_start.function = func;
	m_start.instr = instr;
	m_start.operand = 0;
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
	result.operand = 0;
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
	auto iter = begin();
	for (size_t j = 0; j < i; j++)
		++iter;
	return *iter;
}


HighLevelILIntegerList::operator vector<uint64_t>() const
{
	vector<uint64_t> result;
	for (auto i : *this)
		result.push_back(i);
	return result;
}


const HighLevelILInstruction HighLevelILInstructionList::ListIterator::operator*()
{
	return HighLevelILInstruction(pos.GetFunction(), pos.GetFunction()->GetRawExpr((size_t)*pos), (size_t)*pos);
}


HighLevelILInstructionList::HighLevelILInstructionList(HighLevelILFunction* func,
	const BNHighLevelILInstruction& instr, size_t count): m_list(func, instr, count)
{
}


HighLevelILInstructionList::const_iterator HighLevelILInstructionList::begin() const
{
	const_iterator result;
	result.pos = m_list.begin();
	return result;
}


HighLevelILInstructionList::const_iterator HighLevelILInstructionList::end() const
{
	const_iterator result;
	result.pos = m_list.end();
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
	for (auto& i : *this)
		result.push_back(i);
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


HighLevelILSSAVariableList::HighLevelILSSAVariableList(HighLevelILFunction* func,
	const BNHighLevelILInstruction& instr, size_t count): m_list(func, instr, count & (~1))
{
}


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
	for (auto& i : *this)
		result.push_back(i);
	return result;
}


HighLevelILOperand::HighLevelILOperand(const HighLevelILInstruction& instr,
	HighLevelILOperandUsage usage, size_t operandIndex):
	m_instr(instr), m_usage(usage), m_operandIndex(operandIndex)
{
	auto i = HighLevelILInstructionBase::operandTypeForUsage.find(m_usage);
	if (i == HighLevelILInstructionBase::operandTypeForUsage.end())
		throw HighLevelILInstructionAccessException();
	m_type = i->second;
}


uint64_t HighLevelILOperand::GetInteger() const
{
	if (m_type != IntegerHighLevelOperand)
		throw HighLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsInteger(m_operandIndex);
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


const HighLevelILOperand HighLevelILOperandList::ListIterator::operator*()
{
	HighLevelILOperandUsage usage = *pos;
	auto i = owner->m_operandIndexMap.find(usage);
	if (i == owner->m_operandIndexMap.end())
		throw HighLevelILInstructionAccessException();
	return HighLevelILOperand(owner->m_instr, usage, i->second);
}


HighLevelILOperandList::HighLevelILOperandList(const HighLevelILInstruction& instr,
	const vector<HighLevelILOperandUsage>& usageList,
	const unordered_map<HighLevelILOperandUsage, size_t>& operandIndexMap):
	m_instr(instr), m_usageList(usageList), m_operandIndexMap(operandIndexMap)
{
}


HighLevelILOperandList::const_iterator HighLevelILOperandList::begin() const
{
	const_iterator result;
	result.owner = this;
	result.pos = m_usageList.begin();
	return result;
}


HighLevelILOperandList::const_iterator HighLevelILOperandList::end() const
{
	const_iterator result;
	result.owner = this;
	result.pos = m_usageList.end();
	return result;
}


size_t HighLevelILOperandList::size() const
{
	return m_usageList.size();
}


const HighLevelILOperand HighLevelILOperandList::operator[](size_t i) const
{
	HighLevelILOperandUsage usage = m_usageList[i];
	auto indexMap = m_operandIndexMap.find(usage);
	if (indexMap == m_operandIndexMap.end())
		throw HighLevelILInstructionAccessException();
	return HighLevelILOperand(m_instr, usage, indexMap->second);
}


HighLevelILOperandList::operator vector<HighLevelILOperand>() const
{
	vector<HighLevelILOperand> result;
	for (auto& i : *this)
		result.push_back(i);
	return result;
}


HighLevelILInstruction::HighLevelILInstruction()
{
	operation = HLIL_UNDEF;
	sourceOperand = BN_INVALID_OPERAND;
	size = 0;
	address = 0;
	function = nullptr;
	exprIndex = BN_INVALID_EXPR;
	parent = BN_INVALID_EXPR;
}


HighLevelILInstruction::HighLevelILInstruction(HighLevelILFunction* func,
	const BNHighLevelILInstruction& instr, size_t expr)
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
	parent = instr.parent;
	function = func;
	exprIndex = expr;
}


HighLevelILInstruction::HighLevelILInstruction(const HighLevelILInstructionBase& instr)
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
	parent = instr.parent;
}


HighLevelILOperandList HighLevelILInstructionBase::GetOperands() const
{
	auto usage = operationOperandUsage.find(operation);
	if (usage == operationOperandUsage.end())
		throw HighLevelILInstructionAccessException();
	auto operandIndex = operationOperandIndex.find(operation);
	if (operandIndex == operationOperandIndex.end())
		throw HighLevelILInstructionAccessException();
	return HighLevelILOperandList(*(const HighLevelILInstruction*)this, usage->second, operandIndex->second);
}


uint64_t HighLevelILInstructionBase::GetRawOperandAsInteger(size_t operand) const
{
	return operands[operand];
}


size_t HighLevelILInstructionBase::GetRawOperandAsIndex(size_t operand) const
{
	return (size_t)operands[operand];
}


HighLevelILInstruction HighLevelILInstructionBase::GetRawOperandAsExpr(size_t operand) const
{
	return HighLevelILInstruction(function, function->GetRawExpr(operands[operand]), operands[operand]);
}


Variable HighLevelILInstructionBase::GetRawOperandAsVariable(size_t operand) const
{
	return Variable::FromIdentifier(operands[operand]);
}


SSAVariable HighLevelILInstructionBase::GetRawOperandAsSSAVariable(size_t operand) const
{
	return SSAVariable(Variable::FromIdentifier(operands[operand]), (size_t)operands[operand + 1]);
}


HighLevelILInstructionList HighLevelILInstructionBase::GetRawOperandAsExprList(size_t operand) const
{
	return HighLevelILInstructionList(function, function->GetRawExpr(operands[operand + 1]), operands[operand]);
}


HighLevelILSSAVariableList HighLevelILInstructionBase::GetRawOperandAsSSAVariableList(size_t operand) const
{
	return HighLevelILSSAVariableList(function, function->GetRawExpr(operands[operand + 1]), operands[operand]);
}


void HighLevelILInstructionBase::UpdateRawOperand(size_t operandIndex, ExprId value)
{
	operands[operandIndex] = value;
	function->UpdateInstructionOperand(exprIndex, operandIndex, value);
}


void HighLevelILInstructionBase::UpdateRawOperandAsExprList(size_t operandIndex, const vector<HighLevelILInstruction>& exprs)
{
	vector<ExprId> exprIndexList;
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


void HighLevelILInstructionBase::Replace(ExprId expr)
{
	function->ReplaceExpr(exprIndex, expr);
}


size_t HighLevelILInstructionBase::GetInstructionIndex() const
{
	return function->GetInstructionForExpr(exprIndex);
}


HighLevelILInstruction HighLevelILInstructionBase::GetInstruction() const
{
	return function->GetInstruction(GetInstructionIndex());
}


void HighLevelILInstruction::VisitExprs(const std::function<bool(const HighLevelILInstruction& expr)>& func) const
{
	stack<size_t> toProcess;
	vector<HighLevelILInstruction> exprs;

	toProcess.push(exprIndex);
	while (!toProcess.empty())
	{
		HighLevelILInstruction cur = function->GetExpr(toProcess.top());
		toProcess.pop();
		if (!func(cur))
			continue;
		switch (cur.operation)
		{
		case HLIL_BLOCK:
			exprs = cur.GetBlockExprs<HLIL_BLOCK>();
			for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
				toProcess.push(i->exprIndex);
			break;
		case HLIL_IF:
			toProcess.push(cur.GetFalseExpr<HLIL_IF>().exprIndex);
			toProcess.push(cur.GetTrueExpr<HLIL_IF>().exprIndex);
			toProcess.push(cur.GetConditionExpr<HLIL_IF>().exprIndex);
			break;
		case HLIL_WHILE:
			toProcess.push(cur.GetLoopExpr<HLIL_WHILE>().exprIndex);
			toProcess.push(cur.GetConditionExpr<HLIL_WHILE>().exprIndex);
			break;
		case HLIL_DO_WHILE:
			toProcess.push(cur.GetConditionExpr<HLIL_DO_WHILE>().exprIndex);
			toProcess.push(cur.GetLoopExpr<HLIL_DO_WHILE>().exprIndex);
			break;
		case HLIL_FOR:
			toProcess.push(cur.GetLoopExpr<HLIL_FOR>().exprIndex);
			toProcess.push(cur.GetUpdateExpr<HLIL_FOR>().exprIndex);
			toProcess.push(cur.GetConditionExpr<HLIL_FOR>().exprIndex);
			toProcess.push(cur.GetInitExpr<HLIL_FOR>().exprIndex);
			break;
		case HLIL_SWITCH:
			exprs = cur.GetCases<HLIL_SWITCH>();
			for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
				toProcess.push(i->exprIndex);
			toProcess.push(cur.GetDefaultExpr<HLIL_SWITCH>().exprIndex);
			toProcess.push(cur.GetConditionExpr<HLIL_SWITCH>().exprIndex);
			break;
		case HLIL_CASE:
			toProcess.push(cur.GetTrueExpr<HLIL_CASE>().exprIndex);
			toProcess.push(cur.GetConditionExpr<HLIL_CASE>().exprIndex);
			break;
		case HLIL_ASSIGN:
			toProcess.push(cur.GetSourceExpr<HLIL_ASSIGN>().exprIndex);
			toProcess.push(cur.GetDestExpr<HLIL_ASSIGN>().exprIndex);
			break;
		case HLIL_ASSIGN_UNPACK:
			toProcess.push(cur.GetSourceExpr<HLIL_ASSIGN_UNPACK>().exprIndex);
			exprs = cur.GetDestExprs<HLIL_ASSIGN_UNPACK>();
			for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
				toProcess.push(i->exprIndex);
			break;
		case HLIL_STRUCT_FIELD:
			toProcess.push(cur.GetSourceExpr<HLIL_STRUCT_FIELD>().exprIndex);
			break;
		case HLIL_ARRAY_INDEX:
			toProcess.push(cur.GetIndexExpr<HLIL_ARRAY_INDEX>().exprIndex);
			toProcess.push(cur.GetSourceExpr<HLIL_ARRAY_INDEX>().exprIndex);
			break;
		case HLIL_SPLIT:
			toProcess.push(cur.GetLowExpr<HLIL_SPLIT>().exprIndex);
			toProcess.push(cur.GetHighExpr<HLIL_SPLIT>().exprIndex);
			break;
		case HLIL_DEREF_FIELD:
			toProcess.push(cur.GetSourceExpr<HLIL_DEREF_FIELD>().exprIndex);
			break;
		case HLIL_CALL:
			exprs = cur.GetParameterExprs<HLIL_CALL>();
			for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
				toProcess.push(i->exprIndex);
			toProcess.push(cur.GetDestExpr<HLIL_CALL>().exprIndex);
			break;
		case HLIL_SYSCALL:
			exprs = cur.GetParameterExprs<HLIL_SYSCALL>();
			for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
				toProcess.push(i->exprIndex);
			break;
		case HLIL_TAILCALL:
			exprs = cur.GetParameterExprs<HLIL_TAILCALL>();
			for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
				toProcess.push(i->exprIndex);
			toProcess.push(cur.GetDestExpr<HLIL_TAILCALL>().exprIndex);
			break;
		case HLIL_RET:
			exprs = cur.GetSourceExprs<HLIL_RET>();
			for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
				toProcess.push(i->exprIndex);
			break;
		case HLIL_DEREF:
		case HLIL_ADDRESS_OF:
		case HLIL_NEG:
		case HLIL_NOT:
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
			toProcess.push(cur.AsOneOperand().GetSourceExpr().exprIndex);
			break;
		case HLIL_ADD:
		case HLIL_SUB:
		case HLIL_AND:
		case HLIL_OR:
		case HLIL_XOR:
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
			toProcess.push(cur.AsTwoOperand().GetRightExpr().exprIndex);
			toProcess.push(cur.AsTwoOperand().GetLeftExpr().exprIndex);
			break;
		case HLIL_ADC:
		case HLIL_SBB:
		case HLIL_RLC:
		case HLIL_RRC:
			toProcess.push(cur.AsTwoOperandWithCarry().GetCarryExpr().exprIndex);
			toProcess.push(cur.AsTwoOperandWithCarry().GetRightExpr().exprIndex);
			toProcess.push(cur.AsTwoOperandWithCarry().GetLeftExpr().exprIndex);
			break;
		case HLIL_INTRINSIC:
			exprs = cur.GetParameterExprs<HLIL_INTRINSIC>();
			for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
				toProcess.push(i->exprIndex);
			break;
		default:
			break;
		}
	}
}


ExprId HighLevelILInstruction::CopyTo(HighLevelILFunction* dest) const
{
	return CopyTo(dest, [&](const HighLevelILInstruction& subExpr) {
		return subExpr.CopyTo(dest);
	});
}


ExprId HighLevelILInstruction::CopyTo(HighLevelILFunction* dest,
	const std::function<ExprId(const HighLevelILInstruction& subExpr)>& subExprHandler) const
{
	vector<ExprId> output, params;
	switch (operation)
	{
	case HLIL_NOP:
		return dest->Nop(*this);
	case HLIL_BLOCK:
		for (auto& i : GetBlockExprs<HLIL_BLOCK>())
			params.push_back(subExprHandler(i));
		return dest->Block(params, *this);
	case HLIL_IF:
		return dest->If(subExprHandler(GetConditionExpr<HLIL_IF>()),
			subExprHandler(GetTrueExpr<HLIL_IF>()), subExprHandler(GetFalseExpr<HLIL_IF>()), *this);
	case HLIL_WHILE:
		return dest->While(subExprHandler(GetConditionExpr<HLIL_WHILE>()),
			subExprHandler(GetLoopExpr<HLIL_WHILE>()), *this);
	case HLIL_DO_WHILE:
		return dest->DoWhile(subExprHandler(GetLoopExpr<HLIL_WHILE>()),
			subExprHandler(GetConditionExpr<HLIL_WHILE>()), *this);
	case HLIL_FOR:
		return dest->For(subExprHandler(GetInitExpr<HLIL_FOR>()),
			subExprHandler(GetConditionExpr<HLIL_FOR>()), subExprHandler(GetUpdateExpr<HLIL_FOR>()),
			subExprHandler(GetLoopExpr<HLIL_FOR>()), *this);
	case HLIL_SWITCH:
		for (auto& i : GetCases<HLIL_SWITCH>())
			params.push_back(subExprHandler(i));
		return dest->Switch(subExprHandler(GetConditionExpr<HLIL_SWITCH>()),
			subExprHandler(GetDefaultExpr<HLIL_SWITCH>()), params, *this);
	case HLIL_CASE:
		return dest->Case(subExprHandler(GetConditionExpr<HLIL_CASE>()),
			subExprHandler(GetTrueExpr<HLIL_CASE>()), *this);
	case HLIL_BREAK:
		return dest->Break(*this);
	case HLIL_CONTINUE:
		return dest->Continue(*this);
	case HLIL_ASSIGN:
		return dest->Assign(size, subExprHandler(GetDestExpr<HLIL_ASSIGN>()),
			subExprHandler(GetSourceExpr<HLIL_ASSIGN>()), *this);
	case HLIL_ASSIGN_UNPACK:
		for (auto& i : GetDestExprs<HLIL_ASSIGN_UNPACK>())
			output.push_back(subExprHandler(i));
		return dest->AssignUnpack(output,
			subExprHandler(GetSourceExpr<HLIL_ASSIGN_UNPACK>()), *this);
	case HLIL_VAR:
		return dest->Var(size, GetVariable<HLIL_VAR>(), *this);
	case HLIL_VAR_SSA:
		return dest->VarSSA(size, GetSSAVariable<HLIL_VAR_SSA>(), *this);
	case HLIL_VAR_PHI:
		return dest->VarPhi(GetDestSSAVariable<HLIL_VAR_PHI>(), GetSourceSSAVariables<HLIL_VAR_PHI>(), *this);
	case HLIL_STRUCT_FIELD:
		return dest->StructField(size, subExprHandler(GetSourceExpr<HLIL_STRUCT_FIELD>()),
			GetOffset<HLIL_STRUCT_FIELD>(), *this);
	case HLIL_ARRAY_INDEX:
		return dest->ArrayIndex(size, subExprHandler(GetSourceExpr<HLIL_ARRAY_INDEX>()),
			subExprHandler(GetIndexExpr<HLIL_ARRAY_INDEX>()), *this);
	case HLIL_SPLIT:
		return dest->Split(size, subExprHandler(GetHighExpr<HLIL_SPLIT>()),
			subExprHandler(GetLowExpr<HLIL_SPLIT>()), *this);
	case HLIL_DEREF:
		return dest->Deref(size, subExprHandler(GetSourceExpr<HLIL_DEREF>()), *this);
	case HLIL_DEREF_FIELD:
		return dest->DerefField(size, subExprHandler(GetSourceExpr<HLIL_DEREF_FIELD>()),
			GetOffset<HLIL_DEREF_FIELD>(), *this);
	case HLIL_ADDRESS_OF:
		return dest->AddressOf(subExprHandler(GetSourceExpr<HLIL_ADDRESS_OF>()), *this);
	case HLIL_CALL:
		for (auto& i : GetParameterExprs<HLIL_CALL>())
			params.push_back(subExprHandler(i));
		return dest->Call(subExprHandler(GetDestExpr<HLIL_CALL>()), params, *this);
	case HLIL_SYSCALL:
		for (auto& i : GetParameterExprs<HLIL_SYSCALL>())
			params.push_back(subExprHandler(i));
		return dest->Syscall(params, *this);
	case HLIL_TAILCALL:
		for (auto& i : GetParameterExprs<HLIL_TAILCALL>())
			params.push_back(subExprHandler(i));
		return dest->TailCall(subExprHandler(GetDestExpr<HLIL_TAILCALL>()), params, *this);
	case HLIL_RET:
		for (auto& i : GetSourceExprs<HLIL_RET>())
			params.push_back(subExprHandler(i));
		return dest->Return(params, *this);
	case HLIL_NORET:
		return dest->NoReturn(*this);
	case HLIL_NEG:
	case HLIL_NOT:
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
		return dest->AddExprWithLocation(operation, *this, size,
			subExprHandler(AsOneOperand().GetSourceExpr()));
	case HLIL_ADD:
	case HLIL_SUB:
	case HLIL_AND:
	case HLIL_OR:
	case HLIL_XOR:
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
		return dest->AddExprWithLocation(operation, *this, size,
			subExprHandler(AsTwoOperand().GetLeftExpr()), subExprHandler(AsTwoOperand().GetRightExpr()));
	case HLIL_ADC:
	case HLIL_SBB:
	case HLIL_RLC:
	case HLIL_RRC:
		return dest->AddExprWithLocation(operation, *this, size,
			subExprHandler(AsTwoOperandWithCarry().GetLeftExpr()),
			subExprHandler(AsTwoOperandWithCarry().GetRightExpr()),
			subExprHandler(AsTwoOperandWithCarry().GetCarryExpr()));
	case HLIL_CONST:
		return dest->Const(size, GetConstant<HLIL_CONST>(), *this);
	case HLIL_CONST_PTR:
		return dest->ConstPointer(size, GetConstant<HLIL_CONST_PTR>(), *this);
	case HLIL_EXTERN_PTR:
		return dest->ExternPointer(size, GetConstant<HLIL_EXTERN_PTR>(), GetOffset<HLIL_EXTERN_PTR>(), *this);
	case HLIL_FLOAT_CONST:
		return dest->FloatConstRaw(size, GetConstant<HLIL_FLOAT_CONST>(), *this);
	case HLIL_IMPORT:
		return dest->ImportedAddress(size, GetConstant<HLIL_IMPORT>(), *this);
	case HLIL_BP:
		return dest->Breakpoint(*this);
	case HLIL_TRAP:
		return dest->Trap(GetVector<HLIL_TRAP>(), *this);
	case HLIL_INTRINSIC:
		for (auto& i : GetParameterExprs<HLIL_INTRINSIC>())
			params.push_back(subExprHandler(i));
		return dest->Intrinsic(GetIntrinsic<HLIL_INTRINSIC>(), params, *this);
	case HLIL_UNDEF:
		return dest->Undefined(*this);
	case HLIL_UNIMPL:
		return dest->Unimplemented(*this);
	default:
		throw HighLevelILInstructionAccessException();
	}
}


bool HighLevelILInstruction::GetOperandIndexForUsage(HighLevelILOperandUsage usage, size_t& operandIndex) const
{
	auto operationIter = HighLevelILInstructionBase::operationOperandIndex.find(operation);
	if (operationIter == HighLevelILInstructionBase::operationOperandIndex.end())
		return false;
	auto usageIter = operationIter->second.find(usage);
	if (usageIter == operationIter->second.end())
		return false;
	operandIndex = usageIter->second;
	return true;
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


int64_t HighLevelILInstruction::GetConstant() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(ConstantHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsInteger(operandIndex);
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


size_t HighLevelILInstruction::GetTarget() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(TargetHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsIndex(operandIndex);
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


HighLevelILSSAVariableList HighLevelILInstruction::GetSourceSSAVariables() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(SourceSSAVariablesHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsSSAVariableList(operandIndex);
	throw HighLevelILInstructionAccessException();
}


ExprId HighLevelILFunction::Nop(const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_NOP, loc, 0);
}


ExprId HighLevelILFunction::Block(const std::vector<ExprId>& exprs, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_BLOCK, loc, 0, exprs.size(), AddOperandList(exprs));
}


ExprId HighLevelILFunction::If(ExprId condition, ExprId trueExpr, ExprId falseExpr,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_IF, loc, 0, condition, trueExpr, falseExpr);
}


ExprId HighLevelILFunction::While(ExprId condition, ExprId loopExpr, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_WHILE, loc, 0, condition, loopExpr);
}


ExprId HighLevelILFunction::DoWhile(ExprId loopExpr, ExprId condition, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DO_WHILE, loc, 0, loopExpr, condition);
}


ExprId HighLevelILFunction::For(ExprId initExpr, ExprId condition, ExprId updateExpr, ExprId loopExpr,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FOR, loc, 0, initExpr, condition, updateExpr, loopExpr);
}


ExprId HighLevelILFunction::Switch(ExprId condition, ExprId defaultExpr, const std::vector<ExprId>& cases,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_SWITCH, loc, 0, condition, defaultExpr,
		cases.size(), AddOperandList(cases));
}


ExprId HighLevelILFunction::Case(ExprId condition, ExprId expr, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CASE, loc, 0, condition, expr);
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


ExprId HighLevelILFunction::Goto(size_t target, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_GOTO, loc, 0, target);
}


ExprId HighLevelILFunction::Label(size_t target, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_LABEL, loc, 0, target);
}


ExprId HighLevelILFunction::Assign(size_t size, ExprId dest, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ASSIGN, loc, size, dest, src);
}


ExprId HighLevelILFunction::AssignUnpack(const vector<ExprId>& output, ExprId src,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ASSIGN_UNPACK, loc, 0, output.size(), AddOperandList(output), src);
}


ExprId HighLevelILFunction::Var(size_t size, const Variable& src,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_VAR, loc, size, src.ToIdentifier());
}


ExprId HighLevelILFunction::VarSSA(size_t size, const SSAVariable& src,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_VAR_SSA, loc, size, src.var.ToIdentifier(), src.version);
}


ExprId HighLevelILFunction::VarPhi(const SSAVariable& dest, const vector<SSAVariable>& sources, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_VAR_PHI, loc, 0, dest.var.ToIdentifier(), dest.version,
		sources.size() * 2, AddSSAVariableList(sources));
}


ExprId HighLevelILFunction::StructField(size_t size, ExprId src, uint64_t offset, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_STRUCT_FIELD, loc, size, src, offset);
}


ExprId HighLevelILFunction::Split(size_t size, ExprId high, ExprId low, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_SPLIT, loc, size, high, low);
}


ExprId HighLevelILFunction::ArrayIndex(size_t size, ExprId src, ExprId idx, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_STRUCT_FIELD, loc, size, src, idx);
}


ExprId HighLevelILFunction::Deref(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DEREF, loc, size, src);
}


ExprId HighLevelILFunction::DerefField(size_t size, ExprId src, uint64_t offset, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DEREF_FIELD, loc, size, src, offset);
}


ExprId HighLevelILFunction::AddressOf(ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ADDRESS_OF, loc, 0, src);
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


ExprId HighLevelILFunction::Add(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ADD, loc, size, left, right);
}


ExprId HighLevelILFunction::AddWithCarry(size_t size, ExprId left, ExprId right, ExprId carry,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ADC, loc, size, left, right, carry);
}


ExprId HighLevelILFunction::Sub(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_SUB, loc, size, left, right);
}


ExprId HighLevelILFunction::SubWithBorrow(size_t size, ExprId left, ExprId right, ExprId carry,
	const ILSourceLocation& loc)
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


ExprId HighLevelILFunction::ShiftLeft(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_LSL, loc, size, left, right);
}


ExprId HighLevelILFunction::LogicalShiftRight(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_LSR, loc, size, left, right);
}


ExprId HighLevelILFunction::ArithShiftRight(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ASR, loc, size, left, right);
}


ExprId HighLevelILFunction::RotateLeft(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ROL, loc, size, left, right);
}


ExprId HighLevelILFunction::RotateLeftCarry(size_t size, ExprId left, ExprId right, ExprId carry,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_RRC, loc, size, left, right, carry);
}


ExprId HighLevelILFunction::RotateRight(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ROR, loc, size, left, right);
}


ExprId HighLevelILFunction::RotateRightCarry(size_t size, ExprId left, ExprId right, ExprId carry,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_RRC, loc, size, left, right, carry);
}


ExprId HighLevelILFunction::Mult(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MUL, loc, size, left, right);
}


ExprId HighLevelILFunction::MultDoublePrecSigned(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MULS_DP, loc, size, left, right);
}


ExprId HighLevelILFunction::MultDoublePrecUnsigned(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MULU_DP, loc, size, left, right);
}


ExprId HighLevelILFunction::DivSigned(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DIVS, loc, size, left, right);
}


ExprId HighLevelILFunction::DivUnsigned(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DIVU, loc, size, left, right);
}


ExprId HighLevelILFunction::DivDoublePrecSigned(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DIVS_DP, loc, size, left, right);
}


ExprId HighLevelILFunction::DivDoublePrecUnsigned(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DIVU_DP, loc, size, left, right);
}


ExprId HighLevelILFunction::ModSigned(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MODS, loc, size, left, right);
}


ExprId HighLevelILFunction::ModUnsigned(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MODU, loc, size, left, right);
}


ExprId HighLevelILFunction::ModDoublePrecSigned(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MODS_DP, loc, size, left, right);
}


ExprId HighLevelILFunction::ModDoublePrecUnsigned(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
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


ExprId HighLevelILFunction::Syscall(const vector<ExprId>& params,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_SYSCALL, loc, 0, params.size(), AddOperandList(params));
}


ExprId HighLevelILFunction::TailCall(ExprId dest, const vector<ExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_TAILCALL, loc, 0, dest, params.size(), AddOperandList(params));
}


ExprId HighLevelILFunction::CompareEqual(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CMP_E, loc, size, left, right);
}


ExprId HighLevelILFunction::CompareNotEqual(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CMP_NE, loc, size, left, right);
}


ExprId HighLevelILFunction::CompareSignedLessThan(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CMP_SLT, loc, size, left, right);
}


ExprId HighLevelILFunction::CompareUnsignedLessThan(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CMP_ULT, loc, size, left, right);
}


ExprId HighLevelILFunction::CompareSignedLessEqual(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CMP_SLE, loc, size, left, right);
}


ExprId HighLevelILFunction::CompareUnsignedLessEqual(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CMP_ULE, loc, size, left, right);
}


ExprId HighLevelILFunction::CompareSignedGreaterEqual(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CMP_SGE, loc, size, left, right);
}


ExprId HighLevelILFunction::CompareUnsignedGreaterEqual(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CMP_UGE, loc, size, left, right);
}


ExprId HighLevelILFunction::CompareSignedGreaterThan(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CMP_SGT, loc, size, left, right);
}


ExprId HighLevelILFunction::CompareUnsignedGreaterThan(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CMP_UGT, loc, size, left, right);
}


ExprId HighLevelILFunction::TestBit(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_TEST_BIT, loc, size, left, right);
}


ExprId HighLevelILFunction::BoolToInt(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_BOOL_TO_INT, loc, size, src);
}


ExprId HighLevelILFunction::AddOverflow(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
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


ExprId HighLevelILFunction::Intrinsic(uint32_t intrinsic, const vector<ExprId>& params,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_INTRINSIC, loc, 0, intrinsic,
		params.size(), AddOperandList(params));
}


ExprId HighLevelILFunction::Undefined(const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_UNDEF, loc, 0);
}


ExprId HighLevelILFunction::Unimplemented(const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_UNIMPL, loc, 0);
}


ExprId HighLevelILFunction::UnimplementedMemoryRef(size_t size, ExprId target,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_UNIMPL_MEM, loc, size, target);
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
