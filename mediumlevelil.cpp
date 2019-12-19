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

#include "binaryninjaapi.h"
#include "mediumlevelilinstruction.h"

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


Ref<Function> MediumLevelILFunction::GetFunction() const
{
	BNFunction* func = BNGetMediumLevelILOwnerFunction(m_object);
	if (!func)
		return nullptr;
	return new Function(func);
}


Ref<Architecture> MediumLevelILFunction::GetArchitecture() const
{
	Ref<Function> func = GetFunction();
	if (!func)
		return nullptr;
	return func->GetArchitecture();
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


void MediumLevelILFunction::PrepareToCopyFunction(MediumLevelILFunction* func)
{
	BNPrepareToCopyMediumLevelILFunction(m_object, func->GetObject());
}


void MediumLevelILFunction::PrepareToCopyBlock(BasicBlock* block)
{
	BNPrepareToCopyMediumLevelILBasicBlock(m_object, block->GetObject());
}


BNMediumLevelILLabel* MediumLevelILFunction::GetLabelForSourceInstruction(size_t i)
{
	return BNGetLabelForMediumLevelILSourceInstruction(m_object, i);
}


ExprId MediumLevelILFunction::AddExpr(BNMediumLevelILOperation operation, size_t size,
	ExprId a, ExprId b, ExprId c, ExprId d, ExprId e)
{
	return BNMediumLevelILAddExpr(m_object, operation, size, a, b, c, d, e);
}


ExprId MediumLevelILFunction::AddExprWithLocation(BNMediumLevelILOperation operation, uint64_t addr,
	uint32_t sourceOperand, size_t size, ExprId a, ExprId b, ExprId c, ExprId d, ExprId e)
{
	return BNMediumLevelILAddExprWithLocation(m_object, operation, addr, sourceOperand, size, a, b, c, d, e);
}


ExprId MediumLevelILFunction::AddExprWithLocation(BNMediumLevelILOperation operation, const ILSourceLocation& loc,
	size_t size, ExprId a, ExprId b, ExprId c, ExprId d, ExprId e)
{
	if (loc.valid)
	{
		return BNMediumLevelILAddExprWithLocation(m_object, operation, loc.address, loc.sourceOperand,
			size, a, b, c, d, e);
	}
	return BNMediumLevelILAddExpr(m_object, operation, size, a, b, c, d, e);
}


ExprId MediumLevelILFunction::AddInstruction(size_t expr)
{
	return BNMediumLevelILAddInstruction(m_object, expr);
}


ExprId MediumLevelILFunction::Goto(BNMediumLevelILLabel& label, const ILSourceLocation& loc)
{
	if (loc.valid)
		return BNMediumLevelILGotoWithLocation(m_object, &label, loc.address, loc.sourceOperand);
	return BNMediumLevelILGoto(m_object, &label);
}


ExprId MediumLevelILFunction::If(ExprId operand, BNMediumLevelILLabel& t, BNMediumLevelILLabel& f,
	const ILSourceLocation& loc)
{
	if (loc.valid)
		return BNMediumLevelILIfWithLocation(m_object, operand, &t, &f, loc.address, loc.sourceOperand);
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
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(operands[i]);
	BNMediumLevelILFreeOperandList(operands);
	return result;
}


ExprId MediumLevelILFunction::AddLabelMap(const map<uint64_t, BNMediumLevelILLabel*>& labels)
{
	uint64_t* valueList = new uint64_t[labels.size()];
	BNMediumLevelILLabel** labelList = new BNMediumLevelILLabel*[labels.size()];
	size_t i = 0;
	for (auto& j : labels)
	{
		valueList[i] = j.first;
		labelList[i] = j.second;
		i++;
	}
	ExprId result = (ExprId)BNMediumLevelILAddLabelMap(m_object, valueList, labelList, labels.size());
	delete[] valueList;
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


ExprId MediumLevelILFunction::AddIndexList(const vector<size_t>& operands)
{
	uint64_t* operandList = new uint64_t[operands.size()];
	for (size_t i = 0; i < operands.size(); i++)
		operandList[i] = operands[i];
	ExprId result = (ExprId)BNMediumLevelILAddOperandList(m_object, operandList, operands.size());
	delete[] operandList;
	return result;
}


ExprId MediumLevelILFunction::AddVariableList(const vector<Variable>& vars)
{
	uint64_t* operandList = new uint64_t[vars.size()];
	for (size_t i = 0; i < vars.size(); i++)
		operandList[i] = vars[i].ToIdentifier();
	ExprId result = (ExprId)BNMediumLevelILAddOperandList(m_object, operandList, vars.size());
	delete[] operandList;
	return result;
}


ExprId MediumLevelILFunction::AddSSAVariableList(const vector<SSAVariable>& vars)
{
	uint64_t* operandList = new uint64_t[vars.size() * 2];
	for (size_t i = 0; i < vars.size(); i++)
	{
		operandList[i * 2] = vars[i].var.ToIdentifier();
		operandList[(i * 2) + 1] = vars[i].version;
	}
	ExprId result = (ExprId)BNMediumLevelILAddOperandList(m_object, operandList, vars.size() * 2);
	delete[] operandList;
	return result;
}


BNMediumLevelILInstruction MediumLevelILFunction::GetRawExpr(size_t i) const
{
	return BNGetMediumLevelILByIndex(m_object, i);
}


MediumLevelILInstruction MediumLevelILFunction::operator[](size_t i)
{
	return GetInstruction(i);
}


MediumLevelILInstruction MediumLevelILFunction::GetInstruction(size_t i)
{
	size_t expr = GetIndexForInstruction(i);
	return MediumLevelILInstruction(this, GetRawExpr(expr), expr, i);
}


MediumLevelILInstruction MediumLevelILFunction::GetExpr(size_t i)
{
	return MediumLevelILInstruction(this, GetRawExpr(i), i, GetInstructionForExpr(i));
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


void MediumLevelILFunction::UpdateInstructionOperand(size_t i, size_t operandIndex, ExprId value)
{
	BNUpdateMediumLevelILOperand(m_object, i, operandIndex, value);
}


void MediumLevelILFunction::MarkInstructionForRemoval(size_t i)
{
	BNMarkMediumLevelILInstructionForRemoval(m_object, i);
}


void MediumLevelILFunction::ReplaceInstruction(size_t i, ExprId expr)
{
	BNReplaceMediumLevelILInstruction(m_object, i, expr);
}


void MediumLevelILFunction::ReplaceExpr(size_t expr, size_t newExpr)
{
	BNReplaceMediumLevelILExpr(m_object, expr, newExpr);
}


void MediumLevelILFunction::Finalize()
{
	BNFinalizeMediumLevelILFunction(m_object);
}


void MediumLevelILFunction::GenerateSSAForm(bool analyzeConditionals, bool handleAliases,
	const set<Variable>& knownNotAliases, const set<Variable>& knownAliases)
{
	BNVariable* knownNotAlias = new BNVariable[knownNotAliases.size()];
	BNVariable* knownAlias = new BNVariable[knownAliases.size()];

	size_t i = 0;
	for (auto& j : knownNotAliases)
	{
		knownNotAlias[i].type = j.type;
		knownNotAlias[i].index = j.index;
		knownNotAlias[i].storage = j.storage;
	}

	i = 0;
	for (auto& j : knownAliases)
	{
		knownAlias[i].type = j.type;
		knownAlias[i].index = j.index;
		knownAlias[i].storage = j.storage;
	}

	BNGenerateMediumLevelILSSAForm(m_object, analyzeConditionals, handleAliases, knownNotAlias, knownNotAliases.size(),
		knownAlias, knownAliases.size());
	delete[] knownNotAlias;
	delete[] knownAlias;
}


bool MediumLevelILFunction::GetExprText(Architecture* arch, ExprId expr, vector<InstructionTextToken>& tokens)
{
	size_t count;
	BNInstructionTextToken* list;
	if (!BNGetMediumLevelILExprText(m_object, arch->GetObject(), expr, &list, &count))
		return false;

	tokens = InstructionTextToken::ConvertAndFreeInstructionTextTokenList(list, count);
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

	tokens = InstructionTextToken::ConvertAndFreeInstructionTextTokenList(list, count);
	return true;
}


void MediumLevelILFunction::VisitInstructions(
	const function<void(BasicBlock* block, const MediumLevelILInstruction& instr)>& func)
{
	for (auto& i : GetBasicBlocks())
		for (size_t j = i->GetStart(); j < i->GetEnd(); j++)
			func(i, GetInstruction(j));
}


void MediumLevelILFunction::VisitAllExprs(
	const function<bool(BasicBlock* block, const MediumLevelILInstruction& expr)>& func)
{
	VisitInstructions([&](BasicBlock* block, const MediumLevelILInstruction& instr) {
		instr.VisitExprs([&](const MediumLevelILInstruction& expr) {
			return func(block, expr);
		});
	});
}


vector<Ref<BasicBlock>> MediumLevelILFunction::GetBasicBlocks() const
{
	size_t count;
	BNBasicBlock** blocks = BNGetMediumLevelILBasicBlockList(m_object, &count);

	vector<Ref<BasicBlock>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new BasicBlock(BNNewBasicBlockReference(blocks[i])));

	BNFreeBasicBlockList(blocks, count);
	return result;
}


Ref<BasicBlock> MediumLevelILFunction::GetBasicBlockForInstruction(size_t i) const
{
	BNBasicBlock* block = BNGetMediumLevelILBasicBlockForInstruction(m_object, i);
	if (!block)
		return nullptr;
	return new BasicBlock(block);
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


size_t MediumLevelILFunction::GetSSAVarDefinition(const SSAVariable& var) const
{
	return BNGetMediumLevelILSSAVarDefinition(m_object, &var.var, var.version);
}


size_t MediumLevelILFunction::GetSSAMemoryDefinition(size_t version) const
{
	return BNGetMediumLevelILSSAMemoryDefinition(m_object, version);
}


set<size_t> MediumLevelILFunction::GetSSAVarUses(const SSAVariable& var) const
{
	size_t count;
	size_t* instrs = BNGetMediumLevelILSSAVarUses(m_object, &var.var, var.version, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(instrs[i]);

	BNFreeILInstructionList(instrs);
	return result;
}


set<size_t> MediumLevelILFunction::GetSSAMemoryUses(size_t version) const
{
	size_t count;
	size_t* instrs = BNGetMediumLevelILSSAMemoryUses(m_object, version, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(instrs[i]);

	BNFreeILInstructionList(instrs);
	return result;
}


bool MediumLevelILFunction::IsSSAVarLive(const SSAVariable& var) const
{
	return BNIsMediumLevelILSSAVarLive(m_object, &var.var, var.version);
}


set<size_t> MediumLevelILFunction::GetVariableDefinitions(const Variable& var) const
{
	size_t count;
	size_t* instrs = BNGetMediumLevelILVariableDefinitions(m_object, &var, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(instrs[i]);

	BNFreeILInstructionList(instrs);
	return result;
}


set<size_t> MediumLevelILFunction::GetVariableUses(const Variable& var) const
{
	size_t count;
	size_t* instrs = BNGetMediumLevelILVariableUses(m_object, &var, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(instrs[i]);

	BNFreeILInstructionList(instrs);
	return result;
}


RegisterValue MediumLevelILFunction::GetSSAVarValue(const SSAVariable& var)
{
	BNRegisterValue value = BNGetMediumLevelILSSAVarValue(m_object, &var.var, var.version);
	return RegisterValue::FromAPIObject(value);
}


RegisterValue MediumLevelILFunction::GetExprValue(size_t expr)
{
	BNRegisterValue value = BNGetMediumLevelILExprValue(m_object, expr);
	return RegisterValue::FromAPIObject(value);
}


RegisterValue MediumLevelILFunction::GetExprValue(const MediumLevelILInstruction& expr)
{
	return GetExprValue(expr.exprIndex);
}


PossibleValueSet MediumLevelILFunction::GetPossibleSSAVarValues(const SSAVariable& var, size_t instr)
{
	BNPossibleValueSet value = BNGetMediumLevelILPossibleSSAVarValues(m_object, &var.var, var.version, instr);
	return PossibleValueSet::FromAPIObject(value);
}


PossibleValueSet MediumLevelILFunction::GetPossibleExprValues(size_t expr)
{
	BNPossibleValueSet value = BNGetMediumLevelILPossibleExprValues(m_object, expr);
	return PossibleValueSet::FromAPIObject(value);
}


PossibleValueSet MediumLevelILFunction::GetPossibleExprValues(const MediumLevelILInstruction& expr)
{
	return GetPossibleExprValues(expr.exprIndex);
}


size_t MediumLevelILFunction::GetSSAVarVersionAtInstruction(const Variable& var, size_t instr) const
{
	return BNGetMediumLevelILSSAVarVersionAtILInstruction(m_object, &var, instr);
}


size_t MediumLevelILFunction::GetSSAMemoryVersionAtInstruction(size_t instr) const
{
	return BNGetMediumLevelILSSAMemoryVersionAtILInstruction(m_object, instr);
}


Variable MediumLevelILFunction::GetVariableForRegisterAtInstruction(uint32_t reg, size_t instr) const
{
	return BNGetMediumLevelILVariableForRegisterAtInstruction(m_object, reg, instr);
}


Variable MediumLevelILFunction::GetVariableForFlagAtInstruction(uint32_t flag, size_t instr) const
{
	return BNGetMediumLevelILVariableForFlagAtInstruction(m_object, flag, instr);
}


Variable MediumLevelILFunction::GetVariableForStackLocationAtInstruction(int64_t offset, size_t instr) const
{
	return BNGetMediumLevelILVariableForStackLocationAtInstruction(m_object, offset, instr);
}


RegisterValue MediumLevelILFunction::GetRegisterValueAtInstruction(uint32_t reg, size_t instr)
{
	BNRegisterValue value = BNGetMediumLevelILRegisterValueAtInstruction(m_object, reg, instr);
	return RegisterValue::FromAPIObject(value);
}


RegisterValue MediumLevelILFunction::GetRegisterValueAfterInstruction(uint32_t reg, size_t instr)
{
	BNRegisterValue value = BNGetMediumLevelILRegisterValueAfterInstruction(m_object, reg, instr);
	return RegisterValue::FromAPIObject(value);
}


PossibleValueSet MediumLevelILFunction::GetPossibleRegisterValuesAtInstruction(uint32_t reg, size_t instr)
{
	BNPossibleValueSet value = BNGetMediumLevelILPossibleRegisterValuesAtInstruction(m_object, reg, instr);
	return PossibleValueSet::FromAPIObject(value);
}


PossibleValueSet MediumLevelILFunction::GetPossibleRegisterValuesAfterInstruction(uint32_t reg, size_t instr)
{
	BNPossibleValueSet value = BNGetMediumLevelILPossibleRegisterValuesAfterInstruction(m_object, reg, instr);
	return PossibleValueSet::FromAPIObject(value);
}


RegisterValue MediumLevelILFunction::GetFlagValueAtInstruction(uint32_t flag, size_t instr)
{
	BNRegisterValue value = BNGetMediumLevelILFlagValueAtInstruction(m_object, flag, instr);
	return RegisterValue::FromAPIObject(value);
}


RegisterValue MediumLevelILFunction::GetFlagValueAfterInstruction(uint32_t flag, size_t instr)
{
	BNRegisterValue value = BNGetMediumLevelILFlagValueAfterInstruction(m_object, flag, instr);
	return RegisterValue::FromAPIObject(value);
}


PossibleValueSet MediumLevelILFunction::GetPossibleFlagValuesAtInstruction(uint32_t flag, size_t instr)
{
	BNPossibleValueSet value = BNGetMediumLevelILPossibleFlagValuesAtInstruction(m_object, flag, instr);
	return PossibleValueSet::FromAPIObject(value);
}


PossibleValueSet MediumLevelILFunction::GetPossibleFlagValuesAfterInstruction(uint32_t flag, size_t instr)
{
	BNPossibleValueSet value = BNGetMediumLevelILPossibleFlagValuesAfterInstruction(m_object, flag, instr);
	return PossibleValueSet::FromAPIObject(value);
}


RegisterValue MediumLevelILFunction::GetStackContentsAtInstruction(int32_t offset, size_t len, size_t instr)
{
	BNRegisterValue value = BNGetMediumLevelILStackContentsAtInstruction(m_object, offset, len, instr);
	return RegisterValue::FromAPIObject(value);
}


RegisterValue MediumLevelILFunction::GetStackContentsAfterInstruction(int32_t offset, size_t len, size_t instr)
{
	BNRegisterValue value = BNGetMediumLevelILStackContentsAfterInstruction(m_object, offset, len, instr);
	return RegisterValue::FromAPIObject(value);
}


PossibleValueSet MediumLevelILFunction::GetPossibleStackContentsAtInstruction(int32_t offset, size_t len, size_t instr)
{
	BNPossibleValueSet value = BNGetMediumLevelILPossibleStackContentsAtInstruction(m_object, offset, len, instr);
	return PossibleValueSet::FromAPIObject(value);
}


PossibleValueSet MediumLevelILFunction::GetPossibleStackContentsAfterInstruction(int32_t offset, size_t len, size_t instr)
{
	BNPossibleValueSet value = BNGetMediumLevelILPossibleStackContentsAfterInstruction(m_object, offset, len, instr);
	return PossibleValueSet::FromAPIObject(value);
}


BNILBranchDependence MediumLevelILFunction::GetBranchDependenceAtInstruction(size_t curInstr, size_t branchInstr) const
{
	return BNGetMediumLevelILBranchDependence(m_object, curInstr, branchInstr);
}


unordered_map<size_t, BNILBranchDependence> MediumLevelILFunction::GetAllBranchDependenceAtInstruction(size_t instr) const
{
	size_t count;
	BNILBranchInstructionAndDependence* deps = BNGetAllMediumLevelILBranchDependence(m_object, instr, &count);

	unordered_map<size_t, BNILBranchDependence> result;
	result.reserve(count);
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


Confidence<Ref<Type>> MediumLevelILFunction::GetExprType(size_t expr)
{
	BNTypeWithConfidence result = BNGetMediumLevelILExprType(m_object, expr);
	if (!result.type)
		return nullptr;
	return Confidence<Ref<Type>>(new Type(result.type), result.confidence);
}


Confidence<Ref<Type>> MediumLevelILFunction::GetExprType(const MediumLevelILInstruction& expr)
{
	return GetExprType(expr.exprIndex);
}


Ref<FlowGraph> MediumLevelILFunction::CreateFunctionGraph(DisassemblySettings* settings)
{
	BNFlowGraph* graph = BNCreateMediumLevelILFunctionGraph(m_object, settings ? settings->GetObject() : nullptr);
	return new CoreFlowGraph(graph);
}
