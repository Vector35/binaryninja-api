// Copyright (c) 2015-2017 Vector 35 LLC
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


DisassemblySettings::DisassemblySettings()
{
	m_object = BNCreateDisassemblySettings();
}


DisassemblySettings::DisassemblySettings(BNDisassemblySettings* settings)
{
	m_object = settings;
}


bool DisassemblySettings::IsOptionSet(BNDisassemblyOption option) const
{
	return BNIsDisassemblySettingsOptionSet(m_object, option);
}


void DisassemblySettings::SetOption(BNDisassemblyOption option, bool state)
{
	BNSetDisassemblySettingsOption(m_object, option, state);
}


size_t DisassemblySettings::GetWidth() const
{
	return BNGetDisassemblyWidth(m_object);
}


void DisassemblySettings::SetWidth(size_t width)
{
	BNSetDisassemblyWidth(m_object, width);
}


size_t DisassemblySettings::GetMaximumSymbolWidth() const
{
	return BNGetDisassemblyMaximumSymbolWidth(m_object);
}


void DisassemblySettings::SetMaximumSymbolWidth(size_t width)
{
	BNSetDisassemblyMaximumSymbolWidth(m_object, width);
}


BasicBlock::BasicBlock(BNBasicBlock* block)
{
	m_object = block;
}


Ref<Function> BasicBlock::GetFunction() const
{
	return new Function(BNGetBasicBlockFunction(m_object));
}


Ref<Architecture> BasicBlock::GetArchitecture() const
{
	return new CoreArchitecture(BNGetBasicBlockArchitecture(m_object));
}


uint64_t BasicBlock::GetStart() const
{
	return BNGetBasicBlockStart(m_object);
}


uint64_t BasicBlock::GetEnd() const
{
	return BNGetBasicBlockEnd(m_object);
}


uint64_t BasicBlock::GetLength() const
{
	return BNGetBasicBlockLength(m_object);
}


size_t BasicBlock::GetIndex() const
{
	return BNGetBasicBlockIndex(m_object);
}


vector<BasicBlockEdge> BasicBlock::GetOutgoingEdges() const
{
	size_t count;
	BNBasicBlockEdge* array = BNGetBasicBlockOutgoingEdges(m_object, &count);

	vector<BasicBlockEdge> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		BasicBlockEdge edge;
		edge.type = array[i].type;
		edge.target = array[i].target ? new BasicBlock(BNNewBasicBlockReference(array[i].target)) : nullptr;
		edge.backEdge = array[i].backEdge;
		result.push_back(edge);
	}

	BNFreeBasicBlockEdgeList(array, count);
	return result;
}


vector<BasicBlockEdge> BasicBlock::GetIncomingEdges() const
{
	size_t count;
	BNBasicBlockEdge* array = BNGetBasicBlockIncomingEdges(m_object, &count);

	vector<BasicBlockEdge> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		BasicBlockEdge edge;
		edge.type = array[i].type;
		edge.target = array[i].target ? new BasicBlock(BNNewBasicBlockReference(array[i].target)) : nullptr;
		edge.backEdge = array[i].backEdge;
		result.push_back(edge);
	}

	BNFreeBasicBlockEdgeList(array, count);
	return result;
}


bool BasicBlock::HasUndeterminedOutgoingEdges() const
{
	return BNBasicBlockHasUndeterminedOutgoingEdges(m_object);
}


bool BasicBlock::CanExit() const
{
	return BNBasicBlockCanExit(m_object);
}


set<Ref<BasicBlock>> BasicBlock::GetDominators() const
{
	size_t count;
	BNBasicBlock** blocks = BNGetBasicBlockDominators(m_object, &count);

	set<Ref<BasicBlock>> result;
	for (size_t i = 0; i < count; i++)
		result.insert(new BasicBlock(BNNewBasicBlockReference(blocks[i])));

	BNFreeBasicBlockList(blocks, count);
	return result;
}


set<Ref<BasicBlock>> BasicBlock::GetStrictDominators() const
{
	size_t count;
	BNBasicBlock** blocks = BNGetBasicBlockStrictDominators(m_object, &count);

	set<Ref<BasicBlock>> result;
	for (size_t i = 0; i < count; i++)
		result.insert(new BasicBlock(BNNewBasicBlockReference(blocks[i])));

	BNFreeBasicBlockList(blocks, count);
	return result;
}


Ref<BasicBlock> BasicBlock::GetImmediateDominator() const
{
	BNBasicBlock* result = BNGetBasicBlockImmediateDominator(m_object);
	if (!result)
		return nullptr;
	return new BasicBlock(result);
}


set<Ref<BasicBlock>> BasicBlock::GetDominatorTreeChildren() const
{
	size_t count;
	BNBasicBlock** blocks = BNGetBasicBlockDominatorTreeChildren(m_object, &count);

	set<Ref<BasicBlock>> result;
	for (size_t i = 0; i < count; i++)
		result.insert(new BasicBlock(BNNewBasicBlockReference(blocks[i])));

	BNFreeBasicBlockList(blocks, count);
	return result;
}


set<Ref<BasicBlock>> BasicBlock::GetDominanceFrontier() const
{
	size_t count;
	BNBasicBlock** blocks = BNGetBasicBlockDominanceFrontier(m_object, &count);

	set<Ref<BasicBlock>> result;
	for (size_t i = 0; i < count; i++)
		result.insert(new BasicBlock(BNNewBasicBlockReference(blocks[i])));

	BNFreeBasicBlockList(blocks, count);
	return result;
}


set<Ref<BasicBlock>> BasicBlock::GetIteratedDominanceFrontier(const set<Ref<BasicBlock>>& blocks)
{
	BNBasicBlock** blockSet = new BNBasicBlock*[blocks.size()];
	size_t i = 0;
	for (auto& j : blocks)
		blockSet[i++] = j->GetObject();

	size_t count;
	BNBasicBlock** resultBlocks = BNGetBasicBlockIteratedDominanceFrontier(blockSet, blocks.size(), &count);
	delete[] blockSet;

	set<Ref<BasicBlock>> result;
	for (size_t k = 0; k < count; k++)
		result.insert(new BasicBlock(BNNewBasicBlockReference(resultBlocks[k])));

	BNFreeBasicBlockList(resultBlocks, count);
	return result;
}


void BasicBlock::MarkRecentUse()
{
	BNMarkBasicBlockAsRecentlyUsed(m_object);
}


vector<vector<InstructionTextToken>> BasicBlock::GetAnnotations()
{
	return GetFunction()->GetBlockAnnotations(GetArchitecture(), GetStart());
}


vector<DisassemblyTextLine> BasicBlock::GetDisassemblyText(DisassemblySettings* settings)
{
	size_t count;
	BNDisassemblyTextLine* lines = BNGetBasicBlockDisassemblyText(m_object, settings->GetObject(), &count);

	vector<DisassemblyTextLine> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		DisassemblyTextLine line;
		line.addr = lines[i].addr;
		line.instrIndex = lines[i].instrIndex;
		line.tokens.reserve(lines[i].count);
		for (size_t j = 0; j < lines[i].count; j++)
		{
			InstructionTextToken token;
			token.type = lines[i].tokens[j].type;
			token.text = lines[i].tokens[j].text;
			token.value = lines[i].tokens[j].value;
			token.size = lines[i].tokens[j].size;
			token.operand = lines[i].tokens[j].operand;
			token.context = lines[i].tokens[j].context;
			token.confidence = lines[i].tokens[j].confidence;
			token.address = lines[i].tokens[j].address;
			line.tokens.push_back(token);
		}
		result.push_back(line);
	}

	BNFreeDisassemblyTextLines(lines, count);
	return result;
}


BNHighlightColor BasicBlock::GetBasicBlockHighlight()
{
	return BNGetBasicBlockHighlight(m_object);
}


void BasicBlock::SetAutoBasicBlockHighlight(BNHighlightColor color)
{
	BNSetAutoBasicBlockHighlight(m_object, color);
}


void BasicBlock::SetAutoBasicBlockHighlight(BNHighlightStandardColor color, uint8_t alpha)
{
	BNHighlightColor hc;
	hc.style = StandardHighlightColor;
	hc.color = color;
	hc.mixColor = NoHighlightColor;
	hc.mix = 0;
	hc.r = 0;
	hc.g = 0;
	hc.b = 0;
	hc.alpha = alpha;
	SetAutoBasicBlockHighlight(hc);
}


void BasicBlock::SetAutoBasicBlockHighlight(BNHighlightStandardColor color, BNHighlightStandardColor mixColor,
	uint8_t mix, uint8_t alpha)
{
	BNHighlightColor hc;
	hc.style = MixedHighlightColor;
	hc.color = color;
	hc.mixColor = mixColor;
	hc.mix = mix;
	hc.r = 0;
	hc.g = 0;
	hc.b = 0;
	hc.alpha = alpha;
	SetAutoBasicBlockHighlight(hc);
}


void BasicBlock::SetAutoBasicBlockHighlight(uint8_t r, uint8_t g, uint8_t b, uint8_t alpha)
{
	BNHighlightColor hc;
	hc.style = CustomHighlightColor;
	hc.color = NoHighlightColor;
	hc.mixColor = NoHighlightColor;
	hc.mix = 0;
	hc.r = r;
	hc.g = g;
	hc.b = b;
	hc.alpha = alpha;
	SetAutoBasicBlockHighlight(hc);
}


void BasicBlock::SetUserBasicBlockHighlight(BNHighlightColor color)
{
	BNSetUserBasicBlockHighlight(m_object, color);
}


void BasicBlock::SetUserBasicBlockHighlight(BNHighlightStandardColor color, uint8_t alpha)
{
	BNHighlightColor hc;
	hc.style = StandardHighlightColor;
	hc.color = color;
	hc.mixColor = NoHighlightColor;
	hc.mix = 0;
	hc.r = 0;
	hc.g = 0;
	hc.b = 0;
	hc.alpha = alpha;
	SetUserBasicBlockHighlight(hc);
}


void BasicBlock::SetUserBasicBlockHighlight(BNHighlightStandardColor color, BNHighlightStandardColor mixColor,
	uint8_t mix, uint8_t alpha)
{
	BNHighlightColor hc;
	hc.style = MixedHighlightColor;
	hc.color = color;
	hc.mixColor = mixColor;
	hc.mix = mix;
	hc.r = 0;
	hc.g = 0;
	hc.b = 0;
	hc.alpha = alpha;
	SetUserBasicBlockHighlight(hc);
}


void BasicBlock::SetUserBasicBlockHighlight(uint8_t r, uint8_t g, uint8_t b, uint8_t alpha)
{
	BNHighlightColor hc;
	hc.style = CustomHighlightColor;
	hc.color = NoHighlightColor;
	hc.mixColor = NoHighlightColor;
	hc.mix = 0;
	hc.r = r;
	hc.g = g;
	hc.b = b;
	hc.alpha = alpha;
	SetUserBasicBlockHighlight(hc);
}


bool BasicBlock::IsBackEdge(BasicBlock* source, BasicBlock* target)
{
	for (auto& i : source->GetOutgoingEdges())
	{
		if (i.target->GetObject() == target->GetObject())
			return i.backEdge;
	}
	return false;
}


bool BasicBlock::IsILBlock() const
{
	return BNIsILBasicBlock(m_object);
}


bool BasicBlock::IsLowLevelILBlock() const
{
	return BNIsLowLevelILBasicBlock(m_object);
}


bool BasicBlock::IsMediumLevelILBlock() const
{
	return BNIsMediumLevelILBasicBlock(m_object);
}


Ref<LowLevelILFunction> BasicBlock::GetLowLevelILFunction() const
{
	BNLowLevelILFunction* func = BNGetBasicBlockLowLevelILFunction(m_object);
	if (!func)
		return nullptr;
	return new LowLevelILFunction(func);
}


Ref<MediumLevelILFunction> BasicBlock::GetMediumLevelILFunction() const
{
	BNMediumLevelILFunction* func = BNGetBasicBlockMediumLevelILFunction(m_object);
	if (!func)
		return nullptr;
	return new MediumLevelILFunction(func);
}
