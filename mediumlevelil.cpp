// Copyright (c) 2017-2026 Vector 35 Inc
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

namespace {

// Memoizes the reverse (LLIL-SSA -> MLIL) expr lookups for one LLIL-SSA function.
// The same LLIL-SSA expr is reached from many MLIL exprs, and a reverse query
// derives its result by walking the LLIL-SSA use-def graph rather than reading a
// stored table, so repeating it for each recurrence is what dominates a
// whole-function map build.
class ReverseExprMemo
{
	Ref<LowLevelILFunction> m_llilSsa;
	std::unordered_map<size_t, std::pair<size_t, std::set<size_t>>> m_entries;

public:
	explicit ReverseExprMemo(Ref<LowLevelILFunction> llilSsa) : m_llilSsa(std::move(llilSsa)) {}

	// The MLIL expr that `llilSsaExpr` maps to directly, paired with every MLIL expr it maps to.
	const std::pair<size_t, std::set<size_t>>& Get(size_t llilSsaExpr)
	{
		auto entry = m_entries.find(llilSsaExpr);
		if (entry == m_entries.end())
		{
			entry = m_entries.emplace(llilSsaExpr,
				std::make_pair(m_llilSsa->GetMediumLevelILExprIndex(llilSsaExpr), m_llilSsa->GetMediumLevelILExprIndexes(llilSsaExpr))
			).first;
		}
		return entry->second;
	}
};

}  // unnamed namespace


ILSourceLocation::ILSourceLocation(const struct MediumLevelILInstruction& instr):
	address(instr.address), sourceOperand(instr.sourceOperand), valid(true),
	ilBased(true), ilDirect(true), ilExprIndex(instr.exprIndex)
{}


MediumLevelILLabel::MediumLevelILLabel()
{
	BNMediumLevelILInitLabel(this);
}


void MediumLevelILFunction::RecordMLILToMLILExprMap(size_t newExprIndex, const ILSourceLocation& location)
{
	if (m_translationData && m_translationData->copyingFunction && location.valid && location.ilBased)
	{
		size_t oldExprIndex = location.ilExprIndex;
		if (m_translationData->mlilToMlilExprMap.find(oldExprIndex) == m_translationData->mlilToMlilExprMap.end())
		{
			m_translationData->mlilToMlilExprMap.insert({oldExprIndex, {}});
		}
		m_translationData->mlilToMlilExprMap[oldExprIndex].push_back({ newExprIndex, location.ilDirect });
	}
}


void MediumLevelILFunction::RecordMLILToMLILInstrMap(size_t newInstrIndex, const ILSourceLocation& location)
{
	if (m_translationData && m_translationData->copyingFunction && location.valid && location.ilBased)
	{
		size_t oldExprIndex = location.ilExprIndex;
		size_t oldInstrIndex = m_translationData->copyingFunction->GetInstructionForExpr(oldExprIndex);
		if (m_translationData->mlilToMlilInstrMap.find(oldInstrIndex) == m_translationData->mlilToMlilInstrMap.end())
		{
			m_translationData->mlilToMlilInstrMap.insert({oldInstrIndex, {}});
		}
		m_translationData->mlilToMlilInstrMap[oldInstrIndex].push_back({ newInstrIndex, location.ilDirect });
	}
}


std::unordered_map<size_t /* llil ssa */, size_t /* mlil */> MediumLevelILFunction::GetLLILSSAToMLILInstrMap(bool fromTranslation)
{
	std::unordered_map<size_t /* llil ssa */, size_t /* mlil */> result;
	if (fromTranslation)
	{
		// TODO: Handle LLIL SSA -> MLIL mappings in case someone is brave enough to try
		// lifting LLILSSA->MLIL themselves instead of an MLIL->MLIL translation
		// (which is the only one I've seen people do so far)

		if (m_translationData && m_translationData->copyingFunction)
		{
			for (auto& [oldInstrIndex, newInstrIndices]: m_translationData->mlilToMlilInstrMap)
			{
				// Look up the LLIL SSA instruction for the old instr in its function
				// and then store that mapping for the new function

				for (auto& [newInstrIndex, newDirect]: newInstrIndices)
				{
					// Instructions are always mapped 1 to 1. If the map is marked indirect
					// then just ignore it.
					if (newDirect)
					{
						size_t oldLLILSSAIndex = m_translationData->copyingFunction->GetLowLevelILInstructionIndex(oldInstrIndex);
						if (oldLLILSSAIndex != BN_INVALID_EXPR)
						{
							result[oldLLILSSAIndex] = newInstrIndex;
						}
					}
				}
			}
		}
	}
	else
	{
		for (auto& block: GetBasicBlocks())
		{
			for (size_t instrIndex = block->GetStart(); instrIndex < block->GetEnd(); instrIndex++)
			{
				size_t llilSSAIndex = GetLowLevelILInstructionIndex(instrIndex);
				result[llilSSAIndex] = instrIndex;
			}
		}
	}

	return result;
}


std::vector<BNExprMapInfo> MediumLevelILFunction::GetLLILSSAToMLILExprMap(bool fromTranslation)
{
	std::vector<BNExprMapInfo> result;

	if (fromTranslation)
	{
		// TODO: Handle LLIL SSA -> MLIL mappings in case someone is brave enough to try
		// lifting LLILSSA->MLIL themselves instead of an MLIL->MLIL translation
		// (which is the only one I've seen people do so far)

		ReverseExprMemo reverse(m_translationData->copyingFunction->GetLowLevelIL()->GetSSAForm());
		for (auto& [oldExprIndex, newExprIndices]: m_translationData->mlilToMlilExprMap)
		{
			// Look up the LLIL SSA expression for the old expr in its function
			// And then store that mapping for the new function

			size_t oldLLILSSADirect = m_translationData->copyingFunction->GetLowLevelILExprIndex(oldExprIndex);
			auto oldLLILSSAIndices = m_translationData->copyingFunction->GetLowLevelILExprIndexes(oldExprIndex);
			for (auto& oldLLILSSAIndex: oldLLILSSAIndices)
			{
				const auto& [oldReverseDirect, oldReverseAll] = reverse.Get(oldLLILSSAIndex);
				for (auto& [newExprIndex, newDirect]: newExprIndices)
				{
					BNExprMapInfo info;
					info.lowerIndex = oldLLILSSAIndex;
					info.higherIndex = newExprIndex;
					info.lowerToHigherDirect = newDirect && oldReverseDirect == oldExprIndex;
					info.higherToLowerDirect = newDirect && oldExprIndex == oldLLILSSADirect;
					info.mapLowerToHigher = oldReverseAll.contains(oldExprIndex);
					info.mapHigherToLower = true;
					result.push_back(info);
				}
			}
		}
	}
	else
	{
		ReverseExprMemo reverse(GetLowLevelIL()->GetSSAForm());
		for (auto& block: GetBasicBlocks())
		{
			for (size_t instrIndex = block->GetStart(); instrIndex < block->GetEnd(); instrIndex++)
			{
				GetInstruction(instrIndex).VisitExprs([&](const MediumLevelILInstruction& expr)
				{
					size_t llilSSADirect = GetLowLevelILExprIndex(expr.exprIndex);
					auto llilSSAIndices = GetLowLevelILExprIndexes(expr.exprIndex);
					for (auto& llilSSAIndex: llilSSAIndices)
					{
						const auto& [reverseDirect, reverseAll] = reverse.Get(llilSSAIndex);

						BNExprMapInfo info;
						info.lowerIndex = llilSSAIndex;
						info.higherIndex = expr.exprIndex;
						info.lowerToHigherDirect = reverseDirect == expr.exprIndex;
						info.higherToLowerDirect = llilSSAIndex == llilSSADirect;
						info.mapLowerToHigher = reverseAll.contains(expr.exprIndex);
						info.mapHigherToLower = true;
						result.push_back(info);
					}
					return true;
				});
			}
		}
	}
	return result;
}


MediumLevelILFunction::MediumLevelILFunction(Architecture* arch, Function* func, LowLevelILFunction* lowLevelIL)
{
	m_object = BNCreateMediumLevelILFunction(arch->GetObject(), func ? func->GetObject() : nullptr, lowLevelIL ? lowLevelIL->GetObject() : nullptr);
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
	if (!m_translationData)
	{
		m_translationData = std::make_unique<MediumLevelILFunction::TranslationData>();
	}
	m_translationData->copyingFunction = func;
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


size_t MediumLevelILFunction::CachePossibleValueSet(const PossibleValueSet& pvs)
{
	BNPossibleValueSet ugh = pvs.ToAPIStruct();
	return BNCacheMediumLevelILPossibleValueSet(m_object, &ugh);
}


PossibleValueSet MediumLevelILFunction::GetCachedPossibleValueSet(size_t idx)
{
	BNPossibleValueSet api = BNGetCachedMediumLevelILPossibleValueSet(m_object, idx);
	return PossibleValueSet::FromAPIStruct(api);
}


ExprId MediumLevelILFunction::AddExpr(
    BNMediumLevelILOperation operation, size_t size, ExprId a, ExprId b, ExprId c, ExprId d, ExprId e)
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
	ExprId index;
	if (loc.valid)
	{
		index = BNMediumLevelILAddExprWithLocation(
		    m_object, operation, loc.address, loc.sourceOperand, size, a, b, c, d, e);
	}
	else
	{
		index = BNMediumLevelILAddExpr(m_object, operation, size, a, b, c, d, e);
	}
	RecordMLILToMLILExprMap(index, loc);
	return index;
}


ExprId MediumLevelILFunction::AddInstruction(size_t expr, const ILSourceLocation& loc)
{
	ExprId index = BNMediumLevelILAddInstruction(m_object, expr);
	RecordMLILToMLILInstrMap(index, loc);
	return index;
}


ExprId MediumLevelILFunction::Goto(BNMediumLevelILLabel& label, const ILSourceLocation& loc)
{
	size_t index;
	if (loc.valid)
	{
		index = BNMediumLevelILGotoWithLocation(m_object, &label, loc.address, loc.sourceOperand);
	}
	else
	{
		index = BNMediumLevelILGoto(m_object, &label);
	}
	RecordMLILToMLILExprMap(index, loc);
	return index;
}


ExprId MediumLevelILFunction::If(
    ExprId operand, BNMediumLevelILLabel& t, BNMediumLevelILLabel& f, const ILSourceLocation& loc)
{
	size_t index;
	if (loc.valid)
	{
		index = BNMediumLevelILIfWithLocation(m_object, operand, &t, &f, loc.address, loc.sourceOperand);
	}
	else
	{
		index = BNMediumLevelILIf(m_object, operand, &t, &f);
	}
	RecordMLILToMLILExprMap(index, loc);
	return index;
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


void MediumLevelILFunction::SetExprAttributes(size_t expr, uint32_t attributes)
{
	BNSetMediumLevelILExprAttributes(m_object, expr, attributes);
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
		i++;
	}

	i = 0;
	for (auto& j : knownAliases)
	{
		knownAlias[i].type = j.type;
		knownAlias[i].index = j.index;
		knownAlias[i].storage = j.storage;
		i++;
	}

	BNGenerateMediumLevelILSSAForm(m_object, analyzeConditionals, handleAliases, knownNotAlias, knownNotAliases.size(),
	    knownAlias, knownAliases.size());
	delete[] knownNotAlias;
	delete[] knownAlias;
}


bool MediumLevelILFunction::GetExprText(
    Architecture* arch, ExprId expr, vector<InstructionTextToken>& tokens, DisassemblySettings* settings)
{
	size_t count;
	BNInstructionTextToken* list;
	if (!BNGetMediumLevelILExprText(
	        m_object, arch->GetObject(), expr, &list, &count, settings ? settings->GetObject() : nullptr))
		return false;

	tokens = InstructionTextToken::ConvertAndFreeInstructionTextTokenList(list, count);
	return true;
}


bool MediumLevelILFunction::GetInstructionText(Function* func, Architecture* arch, size_t instr,
    vector<InstructionTextToken>& tokens, DisassemblySettings* settings)
{
	size_t count;
	BNInstructionTextToken* list;
	if (!BNGetMediumLevelILInstructionText(m_object, func ? func->GetObject() : nullptr, arch->GetObject(), instr,
	        &list, &count, settings ? settings->GetObject() : nullptr))
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
		instr.VisitExprs([&](const MediumLevelILInstruction& expr) { return func(block, expr); });
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


bool MediumLevelILFunction::IsSSAVarLiveAt(const SSAVariable& var, const size_t instr) const
{
	return BNIsMediumLevelILSSAVarLiveAt(m_object, &var.var, var.version, instr);
}


bool MediumLevelILFunction::IsVarLiveAt(const Variable& var, const size_t instr) const
{
	return BNIsMediumLevelILVarLiveAt(m_object, &var, instr);
}


set<size_t> MediumLevelILFunction::GetVariableSSAVersions(const Variable& var) const
{
	size_t count;
	size_t* versions = BNGetMediumLevelILVariableSSAVersions(m_object, &var, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(versions[i]);

	BNFreeILInstructionList(versions);
	return result;
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
	return RegisterValue::FromAPIStruct(value);
}


RegisterValue MediumLevelILFunction::GetExprValue(size_t expr)
{
	BNRegisterValue value = BNGetMediumLevelILExprValue(m_object, expr);
	return RegisterValue::FromAPIStruct(value);
}


RegisterValue MediumLevelILFunction::GetExprValue(const MediumLevelILInstruction& expr)
{
	return GetExprValue(expr.exprIndex);
}


PossibleValueSet MediumLevelILFunction::GetPossibleSSAVarValues(
    const SSAVariable& var, size_t instr, const set<BNDataFlowQueryOption>& options)
{
	BNDataFlowQueryOption* optionArray = new BNDataFlowQueryOption[options.size()];
	size_t idx = 0;
	for (auto i : options)
		optionArray[idx++] = i;
	BNPossibleValueSet value =
	    BNGetMediumLevelILPossibleSSAVarValues(m_object, &var.var, var.version, instr, optionArray, options.size());
	delete[] optionArray;
	return PossibleValueSet::FromAPIStruct(value);
}


PossibleValueSet MediumLevelILFunction::GetPossibleExprValues(size_t expr, const set<BNDataFlowQueryOption>& options)
{
	BNDataFlowQueryOption* optionArray = new BNDataFlowQueryOption[options.size()];
	size_t idx = 0;
	for (auto i : options)
		optionArray[idx++] = i;
	BNPossibleValueSet value = BNGetMediumLevelILPossibleExprValues(m_object, expr, optionArray, options.size());
	delete[] optionArray;
	return PossibleValueSet::FromAPIStruct(value);
}


PossibleValueSet MediumLevelILFunction::GetPossibleExprValues(
    const MediumLevelILInstruction& expr, const set<BNDataFlowQueryOption>& options)
{
	return GetPossibleExprValues(expr.exprIndex, options);
}


size_t MediumLevelILFunction::GetSSAVarVersionAtInstruction(const Variable& var, size_t instr) const
{
	return BNGetMediumLevelILSSAVarVersionAtILInstruction(m_object, &var, instr);
}


size_t MediumLevelILFunction::GetSSAVarVersionAfterInstruction(const Variable& var, size_t instr) const
{
	return BNGetMediumLevelILSSAVarVersionAfterILInstruction(m_object, &var, instr);
}


size_t MediumLevelILFunction::GetSSAMemoryVersionAtInstruction(size_t instr) const
{
	return BNGetMediumLevelILSSAMemoryVersionAtILInstruction(m_object, instr);
}


size_t MediumLevelILFunction::GetSSAMemoryVersionAfterInstruction(size_t instr) const
{
	return BNGetMediumLevelILSSAMemoryVersionAfterILInstruction(m_object, instr);
}


Variable MediumLevelILFunction::GetVariableForRegisterAtInstruction(uint32_t reg, size_t instr) const
{
	return BNGetMediumLevelILVariableForRegisterAtInstruction(m_object, reg, instr);
}


Variable MediumLevelILFunction::GetVariableForRegisterAfterInstruction(uint32_t reg, size_t instr) const
{
	return BNGetMediumLevelILVariableForRegisterAfterInstruction(m_object, reg, instr);
}


Variable MediumLevelILFunction::GetVariableForFlagAtInstruction(uint32_t flag, size_t instr) const
{
	return BNGetMediumLevelILVariableForFlagAtInstruction(m_object, flag, instr);
}


Variable MediumLevelILFunction::GetVariableForFlagAfterInstruction(uint32_t flag, size_t instr) const
{
	return BNGetMediumLevelILVariableForFlagAfterInstruction(m_object, flag, instr);
}


Variable MediumLevelILFunction::GetVariableForStackLocationAtInstruction(int64_t offset, size_t instr) const
{
	return BNGetMediumLevelILVariableForStackLocationAtInstruction(m_object, offset, instr);
}


Variable MediumLevelILFunction::GetVariableForStackLocationAfterInstruction(int64_t offset, size_t instr) const
{
	return BNGetMediumLevelILVariableForStackLocationAfterInstruction(m_object, offset, instr);
}


RegisterValue MediumLevelILFunction::GetRegisterValueAtInstruction(uint32_t reg, size_t instr)
{
	BNRegisterValue value = BNGetMediumLevelILRegisterValueAtInstruction(m_object, reg, instr);
	return RegisterValue::FromAPIStruct(value);
}


RegisterValue MediumLevelILFunction::GetRegisterValueAfterInstruction(uint32_t reg, size_t instr)
{
	BNRegisterValue value = BNGetMediumLevelILRegisterValueAfterInstruction(m_object, reg, instr);
	return RegisterValue::FromAPIStruct(value);
}


PossibleValueSet MediumLevelILFunction::GetPossibleRegisterValuesAtInstruction(
    uint32_t reg, size_t instr, const set<BNDataFlowQueryOption>& options)
{
	BNDataFlowQueryOption* optionArray = new BNDataFlowQueryOption[options.size()];
	size_t idx = 0;
	for (auto i : options)
		optionArray[idx++] = i;
	BNPossibleValueSet value =
	    BNGetMediumLevelILPossibleRegisterValuesAtInstruction(m_object, reg, instr, optionArray, options.size());
	delete[] optionArray;
	return PossibleValueSet::FromAPIStruct(value);
}


PossibleValueSet MediumLevelILFunction::GetPossibleRegisterValuesAfterInstruction(
    uint32_t reg, size_t instr, const set<BNDataFlowQueryOption>& options)
{
	BNDataFlowQueryOption* optionArray = new BNDataFlowQueryOption[options.size()];
	size_t idx = 0;
	for (auto i : options)
		optionArray[idx++] = i;
	BNPossibleValueSet value =
	    BNGetMediumLevelILPossibleRegisterValuesAfterInstruction(m_object, reg, instr, optionArray, options.size());
	delete[] optionArray;
	return PossibleValueSet::FromAPIStruct(value);
}


RegisterValue MediumLevelILFunction::GetFlagValueAtInstruction(uint32_t flag, size_t instr)
{
	BNRegisterValue value = BNGetMediumLevelILFlagValueAtInstruction(m_object, flag, instr);
	return RegisterValue::FromAPIStruct(value);
}


RegisterValue MediumLevelILFunction::GetFlagValueAfterInstruction(uint32_t flag, size_t instr)
{
	BNRegisterValue value = BNGetMediumLevelILFlagValueAfterInstruction(m_object, flag, instr);
	return RegisterValue::FromAPIStruct(value);
}


PossibleValueSet MediumLevelILFunction::GetPossibleFlagValuesAtInstruction(
    uint32_t flag, size_t instr, const set<BNDataFlowQueryOption>& options)
{
	BNDataFlowQueryOption* optionArray = new BNDataFlowQueryOption[options.size()];
	size_t idx = 0;
	for (auto i : options)
		optionArray[idx++] = i;
	BNPossibleValueSet value =
	    BNGetMediumLevelILPossibleFlagValuesAtInstruction(m_object, flag, instr, optionArray, options.size());
	delete[] optionArray;
	return PossibleValueSet::FromAPIStruct(value);
}


PossibleValueSet MediumLevelILFunction::GetPossibleFlagValuesAfterInstruction(
    uint32_t flag, size_t instr, const set<BNDataFlowQueryOption>& options)
{
	BNDataFlowQueryOption* optionArray = new BNDataFlowQueryOption[options.size()];
	size_t idx = 0;
	for (auto i : options)
		optionArray[idx++] = i;
	BNPossibleValueSet value =
	    BNGetMediumLevelILPossibleFlagValuesAfterInstruction(m_object, flag, instr, optionArray, options.size());
	delete[] optionArray;
	return PossibleValueSet::FromAPIStruct(value);
}


RegisterValue MediumLevelILFunction::GetStackContentsAtInstruction(int32_t offset, size_t len, size_t instr)
{
	BNRegisterValue value = BNGetMediumLevelILStackContentsAtInstruction(m_object, offset, len, instr);
	return RegisterValue::FromAPIStruct(value);
}


RegisterValue MediumLevelILFunction::GetStackContentsAfterInstruction(int32_t offset, size_t len, size_t instr)
{
	BNRegisterValue value = BNGetMediumLevelILStackContentsAfterInstruction(m_object, offset, len, instr);
	return RegisterValue::FromAPIStruct(value);
}


PossibleValueSet MediumLevelILFunction::GetPossibleStackContentsAtInstruction(
    int32_t offset, size_t len, size_t instr, const set<BNDataFlowQueryOption>& options)
{
	BNDataFlowQueryOption* optionArray = new BNDataFlowQueryOption[options.size()];
	size_t idx = 0;
	for (auto i : options)
		optionArray[idx++] = i;
	BNPossibleValueSet value =
	    BNGetMediumLevelILPossibleStackContentsAtInstruction(m_object, offset, len, instr, optionArray, options.size());
	delete[] optionArray;
	return PossibleValueSet::FromAPIStruct(value);
}


PossibleValueSet MediumLevelILFunction::GetPossibleStackContentsAfterInstruction(
    int32_t offset, size_t len, size_t instr, const set<BNDataFlowQueryOption>& options)
{
	BNDataFlowQueryOption* optionArray = new BNDataFlowQueryOption[options.size()];
	size_t idx = 0;
	for (auto i : options)
		optionArray[idx++] = i;
	BNPossibleValueSet value = BNGetMediumLevelILPossibleStackContentsAfterInstruction(
	    m_object, offset, len, instr, optionArray, options.size());
	delete[] optionArray;
	return PossibleValueSet::FromAPIStruct(value);
}


BNILBranchDependence MediumLevelILFunction::GetBranchDependenceAtInstruction(size_t curInstr, size_t branchInstr) const
{
	return BNGetMediumLevelILBranchDependence(m_object, curInstr, branchInstr);
}


unordered_map<size_t, BNILBranchDependence> MediumLevelILFunction::GetAllBranchDependenceAtInstruction(
    size_t instr) const
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


set<size_t> MediumLevelILFunction::GetLowLevelILExprIndexes(size_t expr) const
{
	size_t count;
	size_t* exprs = BNGetLowLevelILExprIndexes(m_object, expr, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(exprs[i]);

	BNFreeILInstructionList(exprs);
	return result;
}


Ref<HighLevelILFunction> MediumLevelILFunction::GetHighLevelIL() const
{
	BNHighLevelILFunction* func = BNGetHighLevelILForMediumLevelIL(m_object);
	if (!func)
		return nullptr;
	return new HighLevelILFunction(func);
}


size_t MediumLevelILFunction::GetHighLevelILInstructionIndex(size_t instr) const
{
	return BNGetHighLevelILInstructionIndex(m_object, instr);
}


size_t MediumLevelILFunction::GetHighLevelILExprIndex(size_t expr) const
{
	return BNGetHighLevelILExprIndex(m_object, expr);
}


set<size_t> MediumLevelILFunction::GetHighLevelILExprIndexes(size_t expr) const
{
	size_t count;
	size_t* exprs = BNGetHighLevelILExprIndexes(m_object, expr, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(exprs[i]);

	BNFreeILInstructionList(exprs);
	return result;
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


void MediumLevelILFunction::SetExprType(size_t expr, const Confidence<Ref<Type>>& type)
{
	BNTypeWithConfidence tc;
	tc.type = type->GetObject();
	tc.confidence = type.GetConfidence();
	BNSetMediumLevelILExprType(m_object, expr, &tc);
}


void MediumLevelILFunction::SetExprType(const BinaryNinja::MediumLevelILInstruction& expr,
										const Confidence<Ref<BinaryNinja::Type>>& type)
{
	SetExprType(expr.exprIndex, type);
}


Ref<FlowGraph> MediumLevelILFunction::CreateFunctionGraph(DisassemblySettings* settings)
{
	BNFlowGraph* graph = BNCreateMediumLevelILFunctionGraph(m_object, settings ? settings->GetObject() : nullptr);
	return new CoreFlowGraph(graph);
}


Ref<FlowGraph> MediumLevelILFunction::CreateFunctionGraphImmediate(DisassemblySettings* settings)
{
	BNFlowGraph* graph = BNCreateMediumLevelILImmediateFunctionGraph(m_object, settings ? settings->GetObject() : nullptr);
	return new CoreFlowGraph(graph);
}


set<size_t> MediumLevelILFunction::GetLiveInstructionsForVariable(const Variable& var, bool includeLastUse)
{
	size_t count;
	size_t* instrs = BNGetMediumLevelILLiveInstructionsForVariable(m_object, &var, includeLastUse, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(instrs[i]);

	BNFreeILInstructionList(instrs);
	return result;
}


Variable MediumLevelILFunction::GetSplitVariableForDefinition(const Variable& var, size_t instrIndex)
{
	return Variable(
		var.type, BNGetDefaultIndexForMediumLevelILVariableDefinition(m_object, &var, instrIndex), var.storage);
}
