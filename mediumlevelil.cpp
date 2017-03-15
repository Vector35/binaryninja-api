// Copyright (c) 2017 Vector 35 LLC
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

#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


MediumLevelILLabel::MediumLevelILLabel()
{
	BNMediumLevelILInitLabel(this);
}


MediumLevelILFunction::MediumLevelILFunction(Architecture* arch, Function* func)
{
	m_object = BNCreateMediumLevelILFunction(arch->GetObject(), func ? func->GetObject() : nullptr);
}


MediumLevelILFunction::MediumLevelILFunction(BNMediumLevelILFunction* func)
{
	m_object = func;
}


uint64_t MediumLevelILFunction::GetCurrentAddress() const
{
	return BNMediumLevelILGetCurrentAddress(m_object);
}


void MediumLevelILFunction::SetCurrentAddress(Architecture* arch, uint64_t addr)
{
	BNMediumLevelILSetCurrentAddress(m_object, arch ? arch->GetObject() : nullptr, addr);
}


size_t MediumLevelILFunction::GetInstructionStart(Architecture* arch, uint64_t addr)
{
	return BNMediumLevelILGetInstructionStart(m_object, arch ? arch->GetObject() : nullptr, addr);
}


ExprId MediumLevelILFunction::AddExpr(BNMediumLevelILOperation operation, size_t size,
	ExprId a, ExprId b, ExprId c, ExprId d, ExprId e, ExprId f)
{
	return BNMediumLevelILAddExpr(m_object, operation, size, a, b, c, d, e, f);
}


ExprId MediumLevelILFunction::AddInstruction(size_t expr)
{
	return BNMediumLevelILAddInstruction(m_object, expr);
}


ExprId MediumLevelILFunction::SetVar(size_t size, const BNILVariable& var, ExprId src)
{
	return AddExpr(MLIL_SET_VAR, size, ((uint64_t)var.type << 32) | (uint64_t)var.index, var.identifier, src);
}


ExprId MediumLevelILFunction::SetVarField(size_t size, const BNILVariable& var, int64_t offset, ExprId src)
{
	return AddExpr(MLIL_SET_VAR_FIELD, size, ((uint64_t)var.type << 32) | (uint64_t)var.index, var.identifier,
		offset, src);
}


ExprId MediumLevelILFunction::SetVarSplit(size_t size, const BNILVariable& high, const BNILVariable& low, ExprId src)
{
	return AddExpr(MLIL_SET_VAR_SPLIT, size, ((uint64_t)high.type << 32) | (uint64_t)high.index, high.identifier,
		((uint64_t)low.type << 32) | (uint64_t)low.index, low.identifier, src);
}


ExprId MediumLevelILFunction::SetVarSSA(size_t size, const BNILVariable& var, size_t varIndex, ExprId src)
{
	return AddExpr(MLIL_SET_VAR_SSA, size, ((uint64_t)var.type << 32) | (uint64_t)var.index, var.identifier,
		varIndex, src);
}


ExprId MediumLevelILFunction::SetVarFieldSSA(size_t size, const BNILVariable& var, size_t varIndex,
	int64_t offset, ExprId src)
{
	return AddExpr(MLIL_SET_VAR_SSA_FIELD, size, ((uint64_t)var.type << 32) | (uint64_t)var.index, var.identifier,
		varIndex, offset, src);
}


ExprId MediumLevelILFunction::SetVarSplitSSA(size_t size, const BNILVariable& high, size_t highIndex,
	const BNILVariable& low, size_t lowIndex, ExprId src)
{
	return AddExpr(MLIL_SET_VAR_SPLIT_SSA, size,
		AddExpr(MLIL_VAR_SPLIT_DEST_SSA, size, ((uint64_t)high.type << 32) | (uint64_t)high.index,
			high.identifier, highIndex),
		AddExpr(MLIL_VAR_SPLIT_DEST_SSA, size, ((uint64_t)low.type << 32) | (uint64_t)low.index,
			low.identifier, lowIndex), src);
}


ExprId MediumLevelILFunction::SetVarAliased(size_t size, const BNILVariable& var, size_t destIndex,
	size_t srcIndex, ExprId src)
{
	return AddExpr(MLIL_SET_VAR_ALIASED, size, ((uint64_t)var.type << 32) | (uint64_t)var.index, var.identifier,
		destIndex, srcIndex, src);
}


ExprId MediumLevelILFunction::SetVarFieldAliased(size_t size, const BNILVariable& var, size_t destIndex,
	size_t srcIndex, int64_t offset, ExprId src)
{
	return AddExpr(MLIL_SET_VAR_ALIASED_FIELD, size, ((uint64_t)var.type << 32) | (uint64_t)var.index, var.identifier,
		destIndex, srcIndex, offset, src);
}


ExprId MediumLevelILFunction::Var(size_t size, const BNILVariable& var)
{
	return AddExpr(MLIL_VAR, size, ((uint64_t)var.type << 32) | (uint64_t)var.index, var.identifier);
}


ExprId MediumLevelILFunction::VarField(size_t size, const BNILVariable& var, int64_t offset)
{
	return AddExpr(MLIL_VAR_FIELD, size, ((uint64_t)var.type << 32) | (uint64_t)var.index, var.identifier, offset);
}


ExprId MediumLevelILFunction::VarSSA(size_t size, const BNILVariable& var, size_t varIndex)
{
	return AddExpr(MLIL_VAR_SSA, size, ((uint64_t)var.type << 32) | (uint64_t)var.index, var.identifier, varIndex);
}


ExprId MediumLevelILFunction::VarFieldSSA(size_t size, const BNILVariable& var, int64_t offset,
	size_t varIndex)
{
	return AddExpr(MLIL_VAR_SSA_FIELD, size, ((uint64_t)var.type << 32) | (uint64_t)var.index, var.identifier,
		offset, varIndex);
}


ExprId MediumLevelILFunction::VarAliased(size_t size, const BNILVariable& var, size_t memIndex)
{
	return AddExpr(MLIL_VAR_ALIASED, size, ((uint64_t)var.type << 32) | (uint64_t)var.index, var.identifier, memIndex);
}


ExprId MediumLevelILFunction::VarFieldAliased(size_t size, const BNILVariable& var, int64_t offset, size_t memIndex)
{
	return AddExpr(MLIL_VAR_ALIASED_FIELD, size, ((uint64_t)var.type << 32) | (uint64_t)var.index, var.identifier,
		offset, memIndex);
}


ExprId MediumLevelILFunction::AddressOf(size_t size, const BNILVariable& var)
{
	return AddExpr(MLIL_ADDRESS_OF, size, ((uint64_t)var.type << 32) | (uint64_t)var.index, var.identifier);
}


ExprId MediumLevelILFunction::AddressOfField(size_t size, const BNILVariable& var, int64_t offset)
{
	return AddExpr(MLIL_ADDRESS_OF_FIELD, size, ((uint64_t)var.type << 32) | (uint64_t)var.index,
		var.identifier, offset);
}


ExprId MediumLevelILFunction::Goto(BNMediumLevelILLabel& label)
{
	return BNMediumLevelILGoto(m_object, &label);
}


ExprId MediumLevelILFunction::If(ExprId operand, BNMediumLevelILLabel& t, BNMediumLevelILLabel& f)
{
	return BNMediumLevelILIf(m_object, operand, &t, &f);
}


void MediumLevelILFunction::MarkLabel(BNMediumLevelILLabel& label)
{
	BNMediumLevelILMarkLabel(m_object, &label);
}


vector<uint64_t> MediumLevelILFunction::GetOperandList(ExprId expr, size_t listOperand)
{
	size_t count;
	uint64_t* operands = BNMediumLevelILGetOperandList(m_object, expr, listOperand, &count);
	vector<uint64_t> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(operands[i]);
	BNMediumLevelILFreeOperandList(operands);
	return result;
}


ExprId MediumLevelILFunction::AddLabelList(const vector<BNMediumLevelILLabel*>& labels)
{
	BNMediumLevelILLabel** labelList = new BNMediumLevelILLabel*[labels.size()];
	for (size_t i = 0; i < labels.size(); i++)
		labelList[i] = labels[i];
	ExprId result = (ExprId)BNMediumLevelILAddLabelList(m_object, labelList, labels.size());
	delete[] labelList;
	return result;
}


ExprId MediumLevelILFunction::AddOperandList(const vector<ExprId> operands)
{
	uint64_t* operandList = new uint64_t[operands.size()];
	for (size_t i = 0; i < operands.size(); i++)
		operandList[i] = operands[i];
	ExprId result = (ExprId)BNMediumLevelILAddOperandList(m_object, operandList, operands.size());
	delete[] operandList;
	return result;
}


BNILVariable MediumLevelILFunction::GetVariable(ExprId i, size_t varOperand)
{
	BNMediumLevelILInstruction instr = (*this)[i];
	BNILVariable result;
	result.type = (BNILVariableSourceType)(instr.operands[varOperand] >> 32);
	result.index = (uint32_t)instr.operands[varOperand];
	result.identifier = instr.operands[varOperand + 1];
	return result;
}


BNMediumLevelILInstruction MediumLevelILFunction::operator[](size_t i) const
{
	return BNGetMediumLevelILByIndex(m_object, i);
}


size_t MediumLevelILFunction::GetIndexForInstruction(size_t i) const
{
	return BNGetMediumLevelILIndexForInstruction(m_object, i);
}


size_t MediumLevelILFunction::GetInstructionForExpr(size_t expr) const
{
	return BNGetMediumLevelILInstructionForExpr(m_object, expr);
}


size_t MediumLevelILFunction::GetInstructionCount() const
{
	return BNGetMediumLevelILInstructionCount(m_object);
}


size_t MediumLevelILFunction::GetExprCount() const
{
	return BNGetMediumLevelILExprCount(m_object);
}


void MediumLevelILFunction::Finalize()
{
	BNFinalizeMediumLevelILFunction(m_object);
}


bool MediumLevelILFunction::GetExprText(Architecture* arch, ExprId expr, vector<InstructionTextToken>& tokens)
{
	size_t count;
	BNInstructionTextToken* list;
	if (!BNGetMediumLevelILExprText(m_object, arch->GetObject(), expr, &list, &count))
		return false;

	tokens.clear();
	for (size_t i = 0; i < count; i++)
	{
		InstructionTextToken token;
		token.type = list[i].type;
		token.text = list[i].text;
		token.value = list[i].value;
		token.size = list[i].size;
		token.operand = list[i].operand;
		token.context = list[i].context;
		token.address = list[i].address;
		tokens.push_back(token);
	}

	BNFreeInstructionText(list, count);
	return true;
}


bool MediumLevelILFunction::GetInstructionText(Function* func, Architecture* arch, size_t instr,
	vector<InstructionTextToken>& tokens)
{
	size_t count;
	BNInstructionTextToken* list;
	if (!BNGetMediumLevelILInstructionText(m_object, func ? func->GetObject() : nullptr, arch->GetObject(),
		instr, &list, &count))
		return false;

	tokens.clear();
	for (size_t i = 0; i < count; i++)
	{
		InstructionTextToken token;
		token.type = list[i].type;
		token.text = list[i].text;
		token.value = list[i].value;
		token.size = list[i].size;
		token.operand = list[i].operand;
		token.context = list[i].context;
		token.address = list[i].address;
		tokens.push_back(token);
	}

	BNFreeInstructionText(list, count);
	return true;
}


vector<Ref<BasicBlock>> MediumLevelILFunction::GetBasicBlocks() const
{
	size_t count;
	BNBasicBlock** blocks = BNGetMediumLevelILBasicBlockList(m_object, &count);

	vector<Ref<BasicBlock>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new BasicBlock(BNNewBasicBlockReference(blocks[i])));

	BNFreeBasicBlockList(blocks, count);
	return result;
}


Ref<MediumLevelILFunction> MediumLevelILFunction::GetSSAForm() const
{
	BNMediumLevelILFunction* func = BNGetMediumLevelILSSAForm(m_object);
	if (!func)
		return nullptr;
	return new MediumLevelILFunction(func);
}


Ref<MediumLevelILFunction> MediumLevelILFunction::GetNonSSAForm() const
{
	BNMediumLevelILFunction* func = BNGetMediumLevelILNonSSAForm(m_object);
	if (!func)
		return nullptr;
	return new MediumLevelILFunction(func);
}


size_t MediumLevelILFunction::GetSSAInstructionIndex(size_t instr) const
{
	return BNGetMediumLevelILSSAInstructionIndex(m_object, instr);
}


size_t MediumLevelILFunction::GetNonSSAInstructionIndex(size_t instr) const
{
	return BNGetMediumLevelILNonSSAInstructionIndex(m_object, instr);
}


size_t MediumLevelILFunction::GetSSAExprIndex(size_t expr) const
{
	return BNGetMediumLevelILSSAExprIndex(m_object, expr);
}


size_t MediumLevelILFunction::GetNonSSAExprIndex(size_t expr) const
{
	return BNGetMediumLevelILNonSSAExprIndex(m_object, expr);
}


size_t MediumLevelILFunction::GetSSAVarDefinition(const BNILVariable& var, size_t idx) const
{
	return BNGetMediumLevelILSSAVarDefinition(m_object, &var, idx);
}


size_t MediumLevelILFunction::GetSSAMemoryDefinition(size_t idx) const
{
	return BNGetMediumLevelILSSAMemoryDefinition(m_object, idx);
}


set<size_t> MediumLevelILFunction::GetSSAVarUses(const BNILVariable& var, size_t idx) const
{
	size_t count;
	size_t* instrs = BNGetMediumLevelILSSAVarUses(m_object, &var, idx, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(instrs[i]);

	BNFreeILInstructionList(instrs);
	return result;
}


set<size_t> MediumLevelILFunction::GetSSAMemoryUses(size_t idx) const
{
	size_t count;
	size_t* instrs = BNGetMediumLevelILSSAMemoryUses(m_object, idx, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(instrs[i]);

	BNFreeILInstructionList(instrs);
	return result;
}


RegisterValue MediumLevelILFunction::GetSSAVarValue(const BNILVariable& var, size_t idx)
{
	BNRegisterValue value = BNGetMediumLevelILSSAVarValue(m_object, &var, idx);
	return RegisterValue::FromAPIObject(value);
}


RegisterValue MediumLevelILFunction::GetExprValue(size_t expr)
{
	BNRegisterValue value = BNGetMediumLevelILExprValue(m_object, expr);
	return RegisterValue::FromAPIObject(value);
}


RegisterValue MediumLevelILFunction::GetPossibleSSAVarValues(const BNILVariable& var, size_t idx, size_t instr)
{
	BNRegisterValue value = BNGetMediumLevelILPossibleSSAVarValues(m_object, &var, idx, instr);
	return RegisterValue::FromAPIObject(value);
}


RegisterValue MediumLevelILFunction::GetPossibleExprValues(size_t expr)
{
	BNRegisterValue value = BNGetMediumLevelILPossibleExprValues(m_object, expr);
	return RegisterValue::FromAPIObject(value);
}


size_t MediumLevelILFunction::GetSSAVarIndexAtInstruction(const BNILVariable& var, size_t instr) const
{
	return BNGetMediumLevelILSSAVarIndexAtILInstruction(m_object, &var, instr);
}


size_t MediumLevelILFunction::GetSSAMemoryIndexAtInstruction(size_t instr) const
{
	return BNGetMediumLevelILSSAMemoryIndexAtILInstruction(m_object, instr);
}


BNILBranchDependence MediumLevelILFunction::GetBranchDependenceAtInstruction(size_t curInstr, size_t branchInstr) const
{
	return BNGetMediumLevelILBranchDependence(m_object, curInstr, branchInstr);
}


map<size_t, BNILBranchDependence> MediumLevelILFunction::GetAllBranchDependenceAtInstruction(size_t instr) const
{
	size_t count;
	BNILBranchInstructionAndDependence* deps = BNGetAllMediumLevelILBranchDependence(m_object, instr, &count);

	map<size_t, BNILBranchDependence> result;
	for (size_t i = 0; i < count; i++)
		result[deps[i].branch] = deps[i].dependence;

	BNFreeILBranchDependenceList(deps);
	return result;
}


Ref<LowLevelILFunction> MediumLevelILFunction::GetLowLevelIL() const
{
	BNLowLevelILFunction* func = BNGetLowLevelILForMediumLevelIL(m_object);
	if (!func)
		return nullptr;
	return new LowLevelILFunction(func);
}


size_t MediumLevelILFunction::GetLowLevelILInstructionIndex(size_t instr) const
{
	return BNGetLowLevelILInstructionIndex(m_object, instr);
}


size_t MediumLevelILFunction::GetLowLevelILExprIndex(size_t expr) const
{
	return BNGetLowLevelILExprIndex(m_object, expr);
}
