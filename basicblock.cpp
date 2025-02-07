// Copyright (c) 2015-2024 Vector 35 Inc
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


Ref<DisassemblySettings> DisassemblySettings::GetDefaultSettings()
{
	return new DisassemblySettings(BNDefaultDisassemblySettings());
}


Ref<DisassemblySettings> DisassemblySettings::GetDefaultGraphSettings()
{
	return new DisassemblySettings(BNDefaultGraphDisassemblySettings());
}


Ref<DisassemblySettings> DisassemblySettings::GetDefaultLinearSettings()
{
	return new DisassemblySettings(BNDefaultLinearDisassemblySettings());
}


DisassemblySettings* DisassemblySettings::Duplicate()
{
	return new DisassemblySettings(BNDuplicateDisassemblySettings(m_object));
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


size_t DisassemblySettings::GetGutterWidth() const
{
	return BNGetDisassemblyGutterWidth(m_object);
}


void DisassemblySettings::SetGutterWidth(size_t width)
{
	BNSetDisassemblyGutterWidth(m_object, width);
}


BNDisassemblyAddressMode DisassemblySettings::GetAddressMode() const
{
	return BNGetDisassemblyAddressMode(m_object);
}


void DisassemblySettings::SetAddressMode(BNDisassemblyAddressMode mode)
{
	BNSetDisassemblyAddressMode(m_object, mode);
}


uint64_t DisassemblySettings::GetAddressBaseOffset() const
{
	return BNGetDisassemblyAddressBaseOffset(m_object);
}


void DisassemblySettings::SetAddressBaseOffset(uint64_t addressBaseOffset)
{
	BNSetDisassemblyAddressBaseOffset(m_object, addressBaseOffset);
}

BNDisassemblyCallParameterHints DisassemblySettings::GetCallParameterHints() const
{
	return BNGetDisassemblyCallParameterHints(m_object);
}


void DisassemblySettings::SetCallParameterHints(BNDisassemblyCallParameterHints hints)
{
	BNSetDisassemblyCallParameterHints(m_object, hints);
}


DisassemblyTextLine::DisassemblyTextLine()
{
	addr = 0;
	instrIndex = BN_INVALID_EXPR;
	highlight.style = StandardHighlightColor;
	highlight.color = NoHighlightColor;
	highlight.mixColor = NoHighlightColor;
	highlight.mix = 0;
	highlight.r = 0;
	highlight.g = 0;
	highlight.b = 0;
	highlight.alpha = 255;
	typeInfo.hasTypeInfo = false;
	typeInfo.fieldIndex = -1;
	typeInfo.parentType = nullptr;
	typeInfo.offset = 0;
}


size_t DisassemblyTextLine::GetTotalWidth() const
{
	size_t result = 0;
	for (auto& i : tokens)
		result += i.width;
	return result;
}


static void FindAddressAndIndentationTokens(
	const vector<InstructionTextToken>& tokens, const std::function<void(const InstructionTextToken&)>& callback)
{
	size_t startToken = 0;
	for (size_t i = 0; i < tokens.size(); i++)
	{
		if (tokens[i].type == AddressSeparatorToken)
		{
			startToken = i + 1;
			break;
		}
	}

	for (size_t i = 0; i < startToken; i++)
		callback(tokens[i]);
	for (size_t i = startToken; i < tokens.size(); i++)
	{
		if (tokens[i].type == AddressDisplayToken || tokens[i].type == AddressSeparatorToken
			|| tokens[i].type == CollapseStateIndicatorToken)
		{
			callback(tokens[i]);
			continue;
		}

		bool whitespace = true;
		for (auto ch : tokens[i].text)
		{
			if (!isspace(ch))
			{
				whitespace = false;
				break;
			}
		}

		if (!whitespace)
			break;

		callback(tokens[i]);
	}
}


size_t DisassemblyTextLine::GetAddressAndIndentationWidth() const
{
	size_t result = 0;
	FindAddressAndIndentationTokens(tokens, [&](const InstructionTextToken& token) { result += token.width; });
	return result;
}


vector<InstructionTextToken> DisassemblyTextLine::GetAddressAndIndentationTokens() const
{
	vector<InstructionTextToken> result;
	FindAddressAndIndentationTokens(tokens, [&](const InstructionTextToken& token) { result.push_back(token); });
	return result;
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
		edge.fallThrough = array[i].fallThrough;
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
		edge.fallThrough = array[i].fallThrough;
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


void BasicBlock::SetCanExit(bool value)
{
	BNBasicBlockSetCanExit(m_object, value);
}


set<Ref<BasicBlock>> BasicBlock::GetDominators(bool post) const
{
	size_t count;
	BNBasicBlock** blocks = BNGetBasicBlockDominators(m_object, &count, post);

	set<Ref<BasicBlock>> result;
	for (size_t i = 0; i < count; i++)
		result.insert(new BasicBlock(BNNewBasicBlockReference(blocks[i])));

	BNFreeBasicBlockList(blocks, count);
	return result;
}


set<Ref<BasicBlock>> BasicBlock::GetStrictDominators(bool post) const
{
	size_t count;
	BNBasicBlock** blocks = BNGetBasicBlockStrictDominators(m_object, &count, post);

	set<Ref<BasicBlock>> result;
	for (size_t i = 0; i < count; i++)
		result.insert(new BasicBlock(BNNewBasicBlockReference(blocks[i])));

	BNFreeBasicBlockList(blocks, count);
	return result;
}


Ref<BasicBlock> BasicBlock::GetImmediateDominator(bool post) const
{
	BNBasicBlock* result = BNGetBasicBlockImmediateDominator(m_object, post);
	if (!result)
		return nullptr;
	return new BasicBlock(result);
}


set<Ref<BasicBlock>> BasicBlock::GetDominatorTreeChildren(bool post) const
{
	size_t count;
	BNBasicBlock** blocks = BNGetBasicBlockDominatorTreeChildren(m_object, &count, post);

	set<Ref<BasicBlock>> result;
	for (size_t i = 0; i < count; i++)
		result.insert(new BasicBlock(BNNewBasicBlockReference(blocks[i])));

	BNFreeBasicBlockList(blocks, count);
	return result;
}


set<Ref<BasicBlock>> BasicBlock::GetDominanceFrontier(bool post) const
{
	size_t count;
	BNBasicBlock** blocks = BNGetBasicBlockDominanceFrontier(m_object, &count, post);

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
		line.highlight = lines[i].highlight;
		line.tokens = InstructionTextToken::ConvertInstructionTextTokenList(lines[i].tokens, lines[i].count);
		line.tags = Tag::ConvertTagList(lines[i].tags, lines[i].tagCount);
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


void BasicBlock::SetAutoBasicBlockHighlight(
    BNHighlightStandardColor color, BNHighlightStandardColor mixColor, uint8_t mix, uint8_t alpha)
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


void BasicBlock::SetUserBasicBlockHighlight(
    BNHighlightStandardColor color, BNHighlightStandardColor mixColor, uint8_t mix, uint8_t alpha)
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


bool BasicBlock::IsHighLevelILBlock() const
{
	return BNIsHighLevelILBasicBlock(m_object);
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


Ref<HighLevelILFunction> BasicBlock::GetHighLevelILFunction() const
{
	BNHighLevelILFunction* func = BNGetBasicBlockHighLevelILFunction(m_object);
	if (!func)
		return nullptr;
	return new HighLevelILFunction(func);
}


bool BasicBlock::GetInstructionContainingAddress(uint64_t addr, uint64_t* start)
{
	return BNGetBasicBlockInstructionContainingAddress(m_object, addr, start);
}


Ref<BasicBlock> BasicBlock::GetSourceBlock() const
{
	BNBasicBlock* block = BNGetBasicBlockSourceBlock(m_object);
	if (!block)
		return nullptr;
	return new BasicBlock(block);
}
