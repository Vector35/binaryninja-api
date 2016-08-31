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


FunctionGraphBlock::FunctionGraphBlock(BNFunctionGraphBlock* block)
{
	m_object = block;
	m_cachedLinesValid = false;
	m_cachedEdgesValid = false;
}


Ref<Architecture> FunctionGraphBlock::GetArchitecture() const
{
	return new CoreArchitecture(BNGetFunctionGraphBlockArchitecture(m_object));
}


uint64_t FunctionGraphBlock::GetStart() const
{
	return BNGetFunctionGraphBlockStart(m_object);
}


uint64_t FunctionGraphBlock::GetEnd() const
{
	return BNGetFunctionGraphBlockEnd(m_object);
}


int FunctionGraphBlock::GetX() const
{
	return BNGetFunctionGraphBlockX(m_object);
}


int FunctionGraphBlock::GetY() const
{
	return BNGetFunctionGraphBlockY(m_object);
}


int FunctionGraphBlock::GetWidth() const
{
	return BNGetFunctionGraphBlockWidth(m_object);
}


int FunctionGraphBlock::GetHeight() const
{
	return BNGetFunctionGraphBlockHeight(m_object);
}


const vector<DisassemblyTextLine>& FunctionGraphBlock::GetLines()
{
	if (m_cachedLinesValid)
		return m_cachedLines;

	size_t count;
	BNDisassemblyTextLine* lines = BNGetFunctionGraphBlockLines(m_object, &count);

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
	m_cachedLines = result;
	m_cachedLinesValid = true;
	return m_cachedLines;
}


const vector<FunctionGraphEdge>& FunctionGraphBlock::GetOutgoingEdges()
{
	if (m_cachedEdgesValid)
		return m_cachedEdges;

	size_t count;
	BNFunctionGraphEdge* edges = BNGetFunctionGraphBlockOutgoingEdges(m_object, &count);

	vector<FunctionGraphEdge> result;
	for (size_t i = 0; i < count; i++)
	{
		FunctionGraphEdge edge;
		edge.type = edges[i].type;
		edge.target = edges[i].target;
		edge.arch = edges[i].arch ? new CoreArchitecture(edges[i].arch) : nullptr;
		edge.points.insert(edge.points.begin(), &edges[i].points[0], &edges[i].points[edges[i].pointCount]);
		result.push_back(edge);
	}

	BNFreeFunctionGraphBlockOutgoingEdgeList(edges, count);
	m_cachedEdges = result;
	m_cachedEdgesValid = true;
	return m_cachedEdges;
}
