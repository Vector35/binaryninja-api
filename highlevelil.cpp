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
#include "highlevelilinstruction.h"

using namespace BinaryNinja;
using namespace std;


HighLevelILFunction::HighLevelILFunction(Architecture* arch, Function* func)
{
	m_object = BNCreateHighLevelILFunction(arch->GetObject(), func ? func->GetObject() : nullptr);
}


HighLevelILFunction::HighLevelILFunction(BNHighLevelILFunction* func)
{
	m_object = func;
}


Ref<Function> HighLevelILFunction::GetFunction() const
{
	BNFunction* func = BNGetHighLevelILOwnerFunction(m_object);
	if (!func)
		return nullptr;
	return new Function(func);
}


Ref<Architecture> HighLevelILFunction::GetArchitecture() const
{
	Ref<Function> func = GetFunction();
	if (!func)
		return nullptr;
	return func->GetArchitecture();
}


uint64_t HighLevelILFunction::GetCurrentAddress() const
{
	return BNHighLevelILGetCurrentAddress(m_object);
}


void HighLevelILFunction::SetCurrentAddress(Architecture* arch, uint64_t addr)
{
	BNHighLevelILSetCurrentAddress(m_object, arch ? arch->GetObject() : nullptr, addr);
}


HighLevelILInstruction HighLevelILFunction::GetRootExpr()
{
	return GetExpr(BNGetHighLevelILRootExpr(m_object));
}


void HighLevelILFunction::SetRootExpr(ExprId expr)
{
	BNSetHighLevelILRootExpr(m_object, expr);
}


void HighLevelILFunction::SetRootExpr(const HighLevelILInstruction& expr)
{
	BNSetHighLevelILRootExpr(m_object, expr.exprIndex);
}


ExprId HighLevelILFunction::AddExpr(BNHighLevelILOperation operation, size_t size,
	ExprId a, ExprId b, ExprId c, ExprId d, ExprId e)
{
	return BNHighLevelILAddExpr(m_object, operation, size, a, b, c, d, e);
}


ExprId HighLevelILFunction::AddExprWithLocation(BNHighLevelILOperation operation, uint64_t addr,
	uint32_t sourceOperand, size_t size, ExprId a, ExprId b, ExprId c, ExprId d, ExprId e)
{
	return BNHighLevelILAddExprWithLocation(m_object, operation, addr, sourceOperand, size, a, b, c, d, e);
}


ExprId HighLevelILFunction::AddExprWithLocation(BNHighLevelILOperation operation, const ILSourceLocation& loc,
	size_t size, ExprId a, ExprId b, ExprId c, ExprId d, ExprId e)
{
	if (loc.valid)
	{
		return BNHighLevelILAddExprWithLocation(m_object, operation, loc.address, loc.sourceOperand,
			size, a, b, c, d, e);
	}
	return BNHighLevelILAddExpr(m_object, operation, size, a, b, c, d, e);
}


vector<uint64_t> HighLevelILFunction::GetOperandList(ExprId expr, size_t listOperand)
{
	size_t count;
	uint64_t* operands = BNHighLevelILGetOperandList(m_object, expr, listOperand, &count);
	vector<uint64_t> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(operands[i]);
	BNMediumLevelILFreeOperandList(operands);
	return result;
}


ExprId HighLevelILFunction::AddOperandList(const vector<ExprId>& operands)
{
	uint64_t* operandList = new uint64_t[operands.size()];
	for (size_t i = 0; i < operands.size(); i++)
		operandList[i] = operands[i];
	ExprId result = (ExprId)BNHighLevelILAddOperandList(m_object, operandList, operands.size());
	delete[] operandList;
	return result;
}


ExprId HighLevelILFunction::AddIndexList(const vector<size_t>& operands)
{
	uint64_t* operandList = new uint64_t[operands.size()];
	for (size_t i = 0; i < operands.size(); i++)
		operandList[i] = operands[i];
	ExprId result = (ExprId)BNHighLevelILAddOperandList(m_object, operandList, operands.size());
	delete[] operandList;
	return result;
}


ExprId HighLevelILFunction::AddSSAVariableList(const vector<SSAVariable>& vars)
{
	uint64_t* operandList = new uint64_t[vars.size() * 2];
	for (size_t i = 0; i < vars.size(); i++)
	{
		operandList[i * 2] = vars[i].var.ToIdentifier();
		operandList[(i * 2) + 1] = vars[i].version;
	}
	ExprId result = (ExprId)BNHighLevelILAddOperandList(m_object, operandList, vars.size() * 2);
	delete[] operandList;
	return result;
}


BNHighLevelILInstruction HighLevelILFunction::GetRawExpr(size_t i) const
{
	return BNGetHighLevelILByIndex(m_object, i, true);
}


BNHighLevelILInstruction HighLevelILFunction::GetRawNonASTExpr(size_t i) const
{
	return BNGetHighLevelILByIndex(m_object, i, false);
}


HighLevelILInstruction HighLevelILFunction::operator[](size_t i)
{
	return GetInstruction(i);
}


HighLevelILInstruction HighLevelILFunction::GetInstruction(size_t i)
{
	size_t expr = GetIndexForInstruction(i);
	return HighLevelILInstruction(this, GetRawNonASTExpr(expr), expr, false, i);
}


HighLevelILInstruction HighLevelILFunction::GetExpr(size_t i, bool asFullAst)
{
	if (asFullAst)
		return HighLevelILInstruction(this, GetRawExpr(i), i, true, GetInstructionForExpr(i));
	return HighLevelILInstruction(this, GetRawNonASTExpr(i), i, false, GetInstructionForExpr(i));
}


size_t HighLevelILFunction::GetIndexForInstruction(size_t i) const
{
	return BNGetHighLevelILIndexForInstruction(m_object, i);
}


size_t HighLevelILFunction::GetInstructionForExpr(size_t expr) const
{
	return BNGetHighLevelILInstructionForExpr(m_object, expr);
}


size_t HighLevelILFunction::GetInstructionCount() const
{
	return BNGetHighLevelILInstructionCount(m_object);
}


size_t HighLevelILFunction::GetExprCount() const
{
	return BNGetHighLevelILExprCount(m_object);
}


vector<Ref<BasicBlock>> HighLevelILFunction::GetBasicBlocks() const
{
	size_t count;
	BNBasicBlock** blocks = BNGetHighLevelILBasicBlockList(m_object, &count);

	vector<Ref<BasicBlock>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new BasicBlock(BNNewBasicBlockReference(blocks[i])));

	BNFreeBasicBlockList(blocks, count);
	return result;
}


Ref<BasicBlock> HighLevelILFunction::GetBasicBlockForInstruction(size_t i) const
{
	BNBasicBlock* block = BNGetHighLevelILBasicBlockForInstruction(m_object, i);
	if (!block)
		return nullptr;
	return new BasicBlock(block);
}


Ref<HighLevelILFunction> HighLevelILFunction::GetSSAForm() const
{
	BNHighLevelILFunction* func = BNGetHighLevelILSSAForm(m_object);
	if (!func)
		return nullptr;
	return new HighLevelILFunction(func);
}


Ref<HighLevelILFunction> HighLevelILFunction::GetNonSSAForm() const
{
	BNHighLevelILFunction* func = BNGetHighLevelILNonSSAForm(m_object);
	if (!func)
		return nullptr;
	return new HighLevelILFunction(func);
}


size_t HighLevelILFunction::GetSSAInstructionIndex(size_t instr) const
{
	return BNGetHighLevelILSSAInstructionIndex(m_object, instr);
}


size_t HighLevelILFunction::GetNonSSAInstructionIndex(size_t instr) const
{
	return BNGetHighLevelILNonSSAInstructionIndex(m_object, instr);
}


size_t HighLevelILFunction::GetSSAExprIndex(size_t expr) const
{
	return BNGetHighLevelILSSAExprIndex(m_object, expr);
}


size_t HighLevelILFunction::GetNonSSAExprIndex(size_t expr) const
{
	return BNGetHighLevelILNonSSAExprIndex(m_object, expr);
}


size_t HighLevelILFunction::GetSSAVarDefinition(const SSAVariable& var) const
{
	return BNGetHighLevelILSSAVarDefinition(m_object, &var.var, var.version);
}


size_t HighLevelILFunction::GetSSAMemoryDefinition(size_t version) const
{
	return BNGetHighLevelILSSAMemoryDefinition(m_object, version);
}


set<size_t> HighLevelILFunction::GetSSAVarUses(const SSAVariable& var) const
{
	size_t count;
	size_t* instrs = BNGetHighLevelILSSAVarUses(m_object, &var.var, var.version, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(instrs[i]);

	BNFreeILInstructionList(instrs);
	return result;
}


set<size_t> HighLevelILFunction::GetSSAMemoryUses(size_t version) const
{
	size_t count;
	size_t* instrs = BNGetHighLevelILSSAMemoryUses(m_object, version, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(instrs[i]);

	BNFreeILInstructionList(instrs);
	return result;
}


bool HighLevelILFunction::IsSSAVarLive(const SSAVariable& var) const
{
	return BNIsHighLevelILSSAVarLive(m_object, &var.var, var.version);
}


set<size_t> HighLevelILFunction::GetVariableDefinitions(const Variable& var) const
{
	size_t count;
	size_t* instrs = BNGetHighLevelILVariableDefinitions(m_object, &var, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(instrs[i]);

	BNFreeILInstructionList(instrs);
	return result;
}


set<size_t> HighLevelILFunction::GetVariableUses(const Variable& var) const
{
	size_t count;
	size_t* instrs = BNGetHighLevelILVariableUses(m_object, &var, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(instrs[i]);

	BNFreeILInstructionList(instrs);
	return result;
}


size_t HighLevelILFunction::GetSSAVarVersionAtInstruction(const Variable& var, size_t instr) const
{
	return BNGetHighLevelILSSAVarVersionAtILInstruction(m_object, &var, instr);
}


size_t HighLevelILFunction::GetSSAMemoryVersionAtInstruction(size_t instr) const
{
	return BNGetHighLevelILSSAMemoryVersionAtILInstruction(m_object, instr);
}


Ref<MediumLevelILFunction> HighLevelILFunction::GetMediumLevelIL() const
{
	BNMediumLevelILFunction* result = BNGetMediumLevelILForHighLevelILFunction(m_object);
	if (!result)
		return nullptr;
	return new MediumLevelILFunction(result);
}


size_t HighLevelILFunction::GetMediumLevelILExprIndex(size_t expr) const
{
	return BNGetMediumLevelILExprIndexFromHighLevelIL(m_object, expr);
}


set<size_t> HighLevelILFunction::GetMediumLevelILExprIndexes(size_t expr) const
{
	size_t count;
	size_t* exprs = BNGetMediumLevelILExprIndexesFromHighLevelIL(m_object, expr, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(exprs[i]);

	BNFreeILInstructionList(exprs);
	return result;
}


void HighLevelILFunction::UpdateInstructionOperand(size_t i, size_t operandIndex, ExprId value)
{
	BNUpdateHighLevelILOperand(m_object, i, operandIndex, value);
}


void HighLevelILFunction::ReplaceExpr(size_t expr, size_t newExpr)
{
	BNReplaceHighLevelILExpr(m_object, expr, newExpr);
}


void HighLevelILFunction::Finalize()
{
	BNFinalizeHighLevelILFunction(m_object);
}


vector<DisassemblyTextLine> HighLevelILFunction::GetExprText(ExprId expr, bool asFullAst)
{
	size_t count;
	BNDisassemblyTextLine* lines = BNGetHighLevelILExprText(m_object, expr, asFullAst, &count);

	vector<DisassemblyTextLine> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		DisassemblyTextLine line;
		line.addr = lines[i].addr;
		line.instrIndex = lines[i].instrIndex;
		line.highlight = lines[i].highlight;
		line.tokens = InstructionTextToken::ConvertInstructionTextTokenList(lines[i].tokens, lines[i].count);
		line.tags = Tag::ConvertTagList(lines[i].tags, lines[i].tagCount);
		result.push_back(line);
	}

	BNFreeDisassemblyTextLines(lines, count);
	return result;
}


vector<DisassemblyTextLine> HighLevelILFunction::GetExprText(const HighLevelILInstruction& instr, bool asFullAst)
{
	return GetExprText(instr.exprIndex, asFullAst);
}


Confidence<Ref<Type>> HighLevelILFunction::GetExprType(size_t expr)
{
	BNTypeWithConfidence result = BNGetHighLevelILExprType(m_object, expr);
	if (!result.type)
		return nullptr;
	return Confidence<Ref<Type>>(new Type(result.type), result.confidence);
}


Confidence<Ref<Type>> HighLevelILFunction::GetExprType(const HighLevelILInstruction& expr)
{
	return GetExprType(expr.exprIndex);
}


void HighLevelILFunction::VisitAllExprs(
	const function<bool(const HighLevelILInstruction& expr)>& func)
{
	GetRootExpr().VisitExprs([&](const HighLevelILInstruction& expr) {
		return func(expr);
	});
}


Ref<FlowGraph> HighLevelILFunction::CreateFunctionGraph(DisassemblySettings* settings)
{
	BNFlowGraph* graph = BNCreateHighLevelILFunctionGraph(m_object, settings ? settings->GetObject() : nullptr);
	return new CoreFlowGraph(graph);
}


size_t HighLevelILFunction::GetExprIndexForLabel(uint64_t label)
{
	return BNGetHighLevelILExprIndexForLabel(m_object, label);
}


set<size_t> HighLevelILFunction::GetUsesForLabel(uint64_t label)
{
	size_t count;
	size_t* uses = BNGetHighLevelILUsesForLabel(m_object, label, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(uses[i]);

	BNFreeILInstructionList(uses);
	return result;
}
