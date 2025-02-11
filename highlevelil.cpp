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
#include "ffi.h"
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


ExprId HighLevelILFunction::AddExpr(
    BNHighLevelILOperation operation, size_t size, ExprId a, ExprId b, ExprId c, ExprId d, ExprId e)
{
	return BNHighLevelILAddExpr(m_object, operation, size, a, b, c, d, e);
}


ExprId HighLevelILFunction::AddExprWithLocation(BNHighLevelILOperation operation, uint64_t addr, uint32_t sourceOperand,
    size_t size, ExprId a, ExprId b, ExprId c, ExprId d, ExprId e)
{
	return BNHighLevelILAddExprWithLocation(m_object, operation, addr, sourceOperand, size, a, b, c, d, e);
}


ExprId HighLevelILFunction::AddExprWithLocation(BNHighLevelILOperation operation, const ILSourceLocation& loc,
    size_t size, ExprId a, ExprId b, ExprId c, ExprId d, ExprId e)
{
	if (loc.valid)
	{
		return BNHighLevelILAddExprWithLocation(
		    m_object, operation, loc.address, loc.sourceOperand, size, a, b, c, d, e);
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


bool HighLevelILFunction::IsSSAVarLiveAt(const SSAVariable& var, const size_t instr) const
{
	return BNIsHighLevelILSSAVarLiveAt(m_object, &var.var, var.version, instr);
}


bool HighLevelILFunction::IsVarLiveAt(const Variable& var, const size_t instr) const
{
	return BNIsHighLevelILVarLiveAt(m_object, &var, instr);
}


bool HighLevelILFunction::HasSideEffects(const HighLevelILInstruction& instr)
{
	return BNHighLevelILHasSideEffects(instr.function->GetObject(), instr.exprIndex);
}


BNScopeType HighLevelILFunction::GetExprScopeType(const HighLevelILInstruction& instr)
{
	return BNGetHighLevelILExprScopeType(instr.function->GetObject(), instr.exprIndex);
}


set<size_t> HighLevelILFunction::GetVariableSSAVersions(const Variable& var) const
{
	size_t count;
	size_t* versions = BNGetHighLevelILVariableSSAVersions(m_object, &var, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(versions[i]);

	BNFreeILInstructionList(versions);
	return result;
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


void HighLevelILFunction::SetExprAttributes(size_t expr, uint32_t attributes)
{
	BNSetHighLevelILExprAttributes(m_object, expr, attributes);
}


void HighLevelILFunction::Finalize()
{
	BNFinalizeHighLevelILFunction(m_object);
}


void HighLevelILFunction::GenerateSSAForm(const set<Variable>& aliases)
{
	BNVariable* aliasList = new BNVariable[aliases.size()];

	size_t i = 0;
	for (auto& alias : aliases)
	{
		aliasList[i].type = alias.type;
		aliasList[i].index = alias.index;
		aliasList[i].storage = alias.storage;
		i++;
	}

	BNGenerateHighLevelILSSAForm(m_object, aliasList, aliases.size());

	delete[] aliasList;
}


vector<DisassemblyTextLine> HighLevelILFunction::GetExprText(ExprId expr, bool asFullAst, DisassemblySettings* settings)
{
	size_t count;
	BNDisassemblyTextLine* lines =
	    BNGetHighLevelILExprText(m_object, expr, asFullAst, &count, settings ? settings->GetObject() : nullptr);

	vector<DisassemblyTextLine> result = ParseAPIObjectList<DisassemblyTextLine>(lines, count);
	BNFreeDisassemblyTextLines(lines, count);
	return result;
}


vector<DisassemblyTextLine> HighLevelILFunction::GetExprText(
	const HighLevelILInstruction& instr, DisassemblySettings* settings)
{
	return GetExprText(instr.exprIndex, instr.ast, settings);
}


vector<DisassemblyTextLine> HighLevelILFunction::GetInstructionText(size_t i, DisassemblySettings* settings)
{
	HighLevelILInstruction instr = GetInstruction(i);
	return GetExprText(instr, settings);
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


void HighLevelILFunction::SetExprType(size_t expr, const Confidence<Ref<Type>>& type)
{
	BNTypeWithConfidence tc;
	tc.type = type->GetObject();
	tc.confidence = type.GetConfidence();
	BNSetHighLevelILExprType(m_object, expr, &tc);
}


void HighLevelILFunction::SetExprType(const BinaryNinja::HighLevelILInstruction& expr,
										const Confidence<Ref<BinaryNinja::Type>>& type)
{
	SetExprType(expr.exprIndex, type);
}


void HighLevelILFunction::VisitAllExprs(const function<bool(const HighLevelILInstruction& expr)>& func)
{
	GetRootExpr().VisitExprs([&](const HighLevelILInstruction& expr) { return func(expr); });
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


set<Variable> HighLevelILFunction::GetVariables()
{
	size_t count;
	BNVariable* vars = BNGetHighLevelILVariables(m_object, &count);

	set<Variable> result;
	for (size_t i = 0; i < count; ++i)
		result.emplace(vars[i]);

	BNFreeVariableList(vars);
	return result;
}


set<Variable> HighLevelILFunction::GetAliasedVariables()
{
	size_t count;
	BNVariable* vars = BNGetHighLevelILAliasedVariables(m_object, &count);

	set<Variable> result;
	for (size_t i = 0; i < count; ++i)
		result.emplace(vars[i]);

	BNFreeVariableList(vars);
	return result;
}


set<SSAVariable> HighLevelILFunction::GetSSAVariables()
{
	size_t count;
	BNVariable* vars = BNGetHighLevelILVariables(m_object, &count);

	set<SSAVariable> result;
	for (size_t i = 0; i < count; ++i)
	{
		size_t versionCount;
		size_t* versions = BNGetHighLevelILVariableSSAVersions(m_object, &vars[i], &versionCount);
		for (size_t j = 0; j < versionCount; ++j)
			result.emplace(vars[i], versions[j]);
		BNFreeILInstructionList(versions);
	}

	BNFreeVariableList(vars);
	return result;
}


HighLevelILTokenEmitter::CurrentExprGuard::CurrentExprGuard(HighLevelILTokenEmitter& parent, const BNTokenEmitterExpr& expr):
	m_parent(&parent)
{
	m_expr = BNHighLevelILTokenEmitterSetCurrentExpr(m_parent->m_object, expr);
}


HighLevelILTokenEmitter::CurrentExprGuard::~CurrentExprGuard()
{
	BNHighLevelILTokenEmitterRestoreCurrentExpr(m_parent->m_object, m_expr);
}


HighLevelILTokenEmitter::HighLevelILTokenEmitter(BNHighLevelILTokenEmitter* emitter)
{
	m_object = emitter;
}

void HighLevelILTokenEmitter::PrependCollapseIndicator()
{
	BNHighLevelILTokenPrependCollapseBlankIndicator(m_object);
}


void HighLevelILTokenEmitter::PrependCollapseIndicator(Ref<Function> function, const HighLevelILInstruction& instr, uint64_t designator)
{
	if (!HasCollapsableRegions())
		return;

	// Insert the collapse indicator at the beginning of the line if one isn't already there or the
	// one that is there is empty
	auto context  = HighLevelILInstruction::CanCollapse(instr.operation) ?
					(function && function->IsInstructionCollapsed(instr, designator) ? ContentCollapsedContext : ContentExpandedContext) :
					ContentCollapsiblePadding;

	PrependCollapseIndicator(context, instr.GetInstructionHash(designator));
}

void HighLevelILTokenEmitter::PrependCollapseIndicator(BNInstructionTextTokenContext context, uint64_t hash)
{
	BNHighLevelILTokenPrependCollapseIndicator(m_object, context, hash);
}

bool HighLevelILTokenEmitter::HasCollapsableRegions()
{
	return BNHighLevelILTokenEmitterHasCollapsableRegions(m_object);
}


void HighLevelILTokenEmitter::SetHasCollapsableRegions(bool state)
{
	BNHighLevelILTokenEmitterSetHasCollapsableRegions(m_object, state);
}


void HighLevelILTokenEmitter::InitLine()
{
	BNHighLevelILTokenEmitterInitLine(m_object);
}


void HighLevelILTokenEmitter::NewLine()
{
	BNHighLevelILTokenEmitterNewLine(m_object);
}


void HighLevelILTokenEmitter::IncreaseIndent()
{
	BNHighLevelILTokenEmitterIncreaseIndent(m_object);
}


void HighLevelILTokenEmitter::DecreaseIndent()
{
	BNHighLevelILTokenEmitterDecreaseIndent(m_object);
}


void HighLevelILTokenEmitter::ScopeSeparator()
{
	BNHighLevelILTokenEmitterScopeSeparator(m_object);
}


void HighLevelILTokenEmitter::BeginScope(BNScopeType scopeType)
{
	BNHighLevelILTokenEmitterBeginScope(m_object, scopeType);
}


void HighLevelILTokenEmitter::EndScope(BNScopeType scopeType)
{
	BNHighLevelILTokenEmitterEndScope(m_object, scopeType);
}


void HighLevelILTokenEmitter::ScopeContinuation(bool forceSameLine)
{
	BNHighLevelILTokenEmitterScopeContinuation(m_object, forceSameLine);
}


void HighLevelILTokenEmitter::FinalizeScope()
{
	BNHighLevelILTokenEmitterFinalizeScope(m_object);
}


void HighLevelILTokenEmitter::NoIndentForThisLine()
{
	BNHighLevelILTokenEmitterNoIndentForThisLine(m_object);
}


void HighLevelILTokenEmitter::BeginForceZeroConfidence()
{
	BNHighLevelILTokenEmitterBeginForceZeroConfidence(m_object);
}


void HighLevelILTokenEmitter::EndForceZeroConfidence()
{
	BNHighLevelILTokenEmitterEndForceZeroConfidence(m_object);
}


HighLevelILTokenEmitter::CurrentExprGuard HighLevelILTokenEmitter::SetCurrentExpr(const HighLevelILInstruction& expr)
{
	return CurrentExprGuard(*this, {expr.address, expr.sourceOperand, expr.exprIndex, expr.GetInstructionIndex()});
}


void HighLevelILTokenEmitter::Finalize()
{
	BNHighLevelILTokenEmitterFinalize(m_object);
}


void HighLevelILTokenEmitter::AppendOpenParen()
{
	BNHighLevelILTokenEmitterAppendOpenParen(m_object);
}


void HighLevelILTokenEmitter::AppendCloseParen()
{
	BNHighLevelILTokenEmitterAppendCloseParen(m_object);
}


void HighLevelILTokenEmitter::AppendOpenBracket()
{
	BNHighLevelILTokenEmitterAppendOpenBracket(m_object);
}


void HighLevelILTokenEmitter::AppendCloseBracket()
{
	BNHighLevelILTokenEmitterAppendCloseBracket(m_object);
}


void HighLevelILTokenEmitter::AppendOpenBrace()
{
	BNHighLevelILTokenEmitterAppendOpenBrace(m_object);
}


void HighLevelILTokenEmitter::AppendCloseBrace()
{
	BNHighLevelILTokenEmitterAppendCloseBrace(m_object);
}


void HighLevelILTokenEmitter::AppendSemicolon()
{
	BNHighLevelILTokenEmitterAppendSemicolon(m_object);
}


vector<InstructionTextToken> HighLevelILTokenEmitter::GetCurrentTokens() const
{
	size_t count = 0;
    BNInstructionTextToken* tokens = BNHighLevelILTokenEmitterGetCurrentTokens(m_object, &count);
	return InstructionTextToken::ConvertAndFreeInstructionTextTokenList(tokens, count);
}


void HighLevelILTokenEmitter::SetBraceRequirement(BNBraceRequirement required)
{
	BNHighLevelILTokenEmitterSetBraceRequirement(m_object, required);
}


void HighLevelILTokenEmitter::SetBracesAroundSwitchCases(bool braces)
{
	BNHighLevelILTokenEmitterSetBracesAroundSwitchCases(m_object, braces);
}


void HighLevelILTokenEmitter::SetDefaultBracesOnSameLine(bool sameLine)
{
	BNHighLevelILTokenEmitterSetDefaultBracesOnSameLine(m_object, sameLine);
}


void HighLevelILTokenEmitter::SetSimpleScopeAllowed(bool allowed)
{
	BNHighLevelILTokenEmitterSetSimpleScopeAllowed(m_object, allowed);
}


BNBraceRequirement HighLevelILTokenEmitter::GetBraceRequirement() const
{
	return BNHighLevelILTokenEmitterGetBraceRequirement(m_object);
}


bool HighLevelILTokenEmitter::HasBracesAroundSwitchCases() const
{
	return BNHighLevelILTokenEmitterHasBracesAroundSwitchCases(m_object);
}


bool HighLevelILTokenEmitter::GetDefaultBracesOnSameLine() const
{
	return BNHighLevelILTokenEmitterGetDefaultBracesOnSameLine(m_object);
}


bool HighLevelILTokenEmitter::IsSimpleScopeAllowed() const
{
	return BNHighLevelILTokenEmitterIsSimpleScopeAllowed(m_object);
}


vector<DisassemblyTextLine> HighLevelILTokenEmitter::GetLines() const
{
    size_t count = 0;
    BNDisassemblyTextLine* lines = BNHighLevelILTokenEmitterGetLines(m_object, &count);

	vector<DisassemblyTextLine> result = ParseAPIObjectList<DisassemblyTextLine>(lines, count);
    BNFreeDisassemblyTextLines(lines, count);
	return result;
}


void HighLevelILTokenEmitter::AppendSizeToken(size_t size, BNInstructionTextTokenType type)
{
	BNAddHighLevelILSizeToken(size, type, m_object);
}


void HighLevelILTokenEmitter::AppendFloatSizeToken(size_t size, BNInstructionTextTokenType type)
{
	BNAddHighLevelILFloatSizeToken(size, type, m_object);
}


void HighLevelILTokenEmitter::AppendVarTextToken(const Variable& var, const HighLevelILInstruction& instr, size_t size)
{
	BNAddHighLevelILVarTextToken(instr.function->GetObject(), &var, m_object, instr.exprIndex, size);
}


void HighLevelILTokenEmitter::AppendIntegerTextToken(const HighLevelILInstruction& instr, int64_t val, size_t size)
{
	BNAddHighLevelILIntegerTextToken(instr.function->GetObject(), instr.exprIndex, val, size, m_object);
}


void HighLevelILTokenEmitter::AppendArrayIndexToken(
	const HighLevelILInstruction& instr, int64_t val, size_t size, uint64_t address)
{
	BNAddHighLevelILArrayIndexToken(instr.function->GetObject(), instr.exprIndex, val, size, m_object, address);
}


BNSymbolDisplayResult HighLevelILTokenEmitter::AppendPointerTextToken(const HighLevelILInstruction& instr, int64_t val,
	DisassemblySettings* settings, BNSymbolDisplayType symbolDisplay, BNOperatorPrecedence precedence,
	bool allowShortString)
{
	return BNAddHighLevelILPointerTextToken(instr.function->GetObject(), instr.exprIndex, val, m_object,
		settings ? settings->GetObject() : nullptr, symbolDisplay, precedence, allowShortString);
}


void HighLevelILTokenEmitter::AppendConstantTextToken(const HighLevelILInstruction& instr, int64_t val, size_t size,
	DisassemblySettings* settings, BNOperatorPrecedence precedence)
{
	BNAddHighLevelILConstantTextToken(instr.function->GetObject(), instr.exprIndex, val, size, m_object,
		settings ? settings->GetObject() : nullptr, precedence);
}


void HighLevelILTokenEmitter::AddNamesForOuterStructureMembers(
	BinaryView* data, Type* type, const HighLevelILInstruction& var, vector<string>& nameList)
{
	size_t nameCount = 0;
	char** names = BNAddNamesForOuterStructureMembers(
		data->GetObject(), type->GetObject(), var.function->GetObject(), var.exprIndex, &nameCount);
	vector<string> newNames;
	newNames.reserve(nameCount);
	for (size_t i = 0; i < nameCount; i++)
		newNames.push_back(names[i]);
	BNFreeStringList(names, nameCount);
	nameList.insert(nameList.begin(), newNames.begin(), newNames.end());
}
