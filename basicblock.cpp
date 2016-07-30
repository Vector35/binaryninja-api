// Copyright (c) 2015-2016 Vector 35 LLC
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


vector<BasicBlockEdge> BasicBlock::GetOutgoingEdges() const
{
	size_t count;
	BNBasicBlockEdge* array = BNGetBasicBlockOutgoingEdges(m_object, &count);

	vector<BasicBlockEdge> result;
	for (size_t i = 0; i < count; i++)
	{
		BasicBlockEdge edge;
		edge.type = array[i].type;
		edge.target = array[i].target;
		edge.arch = array[i].arch ? new CoreArchitecture(array[i].arch) : nullptr;
		result.push_back(edge);
	}

	BNFreeBasicBlockOutgoingEdgeList(array);
	return result;
}


bool BasicBlock::HasUndeterminedOutgoingEdges() const
{
	return BNBasicBlockHasUndeterminedOutgoingEdges(m_object);
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
	for (size_t i = 0; i < count; i++)
	{
		DisassemblyTextLine line;
		line.addr = lines[i].addr;
		for (size_t j = 0; j < lines[i].count; j++)
		{
			InstructionTextToken token;
			token.type = lines[i].tokens[j].type;
			token.text = lines[i].tokens[j].text;
			token.value = lines[i].tokens[j].value;
			token.size = lines[i].tokens[j].size;
			token.operand = lines[i].tokens[j].operand;
			line.tokens.push_back(token);
		}
		result.push_back(line);
	}

	BNFreeDisassemblyTextLines(lines, count);
	return result;
}
