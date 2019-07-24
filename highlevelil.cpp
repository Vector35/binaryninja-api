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


ExprId HighLevelILFunction::AddOperandList(const vector<ExprId> operands)
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
	return BNGetHighLevelILByIndex(m_object, i);
}


HighLevelILInstruction HighLevelILFunction::operator[](size_t i)
{
	return GetInstruction(i);
}


HighLevelILInstruction HighLevelILFunction::GetInstruction(size_t i)
{
	size_t expr = GetIndexForInstruction(i);
	return HighLevelILInstruction(this, GetRawExpr(expr), expr);
}


HighLevelILInstruction HighLevelILFunction::GetExpr(size_t i)
{
	return HighLevelILInstruction(this, GetRawExpr(i), i);
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
