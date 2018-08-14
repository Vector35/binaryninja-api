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


FlowGraphNode::FlowGraphNode(FlowGraph* graph)
{
	m_object = BNCreateFlowGraphNode(graph->GetObject());
	m_cachedLinesValid = false;
	m_cachedEdgesValid = false;
}


FlowGraphNode::FlowGraphNode(BNFlowGraphNode* node)
{
	m_object = node;
	m_cachedLinesValid = false;
	m_cachedEdgesValid = false;
}


Ref<BasicBlock> FlowGraphNode::GetBasicBlock() const
{
	BNBasicBlock* block = BNGetFlowGraphBasicBlock(m_object);
	if (!block)
		return nullptr;
	return new BasicBlock(block);
}


void FlowGraphNode::SetBasicBlock(BasicBlock* block)
{
	BNSetFlowGraphBasicBlock(m_object, block ? block->GetObject() : nullptr);
}


int FlowGraphNode::GetX() const
{
	return BNGetFlowGraphNodeX(m_object);
}


int FlowGraphNode::GetY() const
{
	return BNGetFlowGraphNodeY(m_object);
}


int FlowGraphNode::GetWidth() const
{
	return BNGetFlowGraphNodeWidth(m_object);
}


int FlowGraphNode::GetHeight() const
{
	return BNGetFlowGraphNodeHeight(m_object);
}


const vector<DisassemblyTextLine>& FlowGraphNode::GetLines()
{
	if (m_cachedLinesValid)
		return m_cachedLines;

	size_t count;
	BNDisassemblyTextLine* lines = BNGetFlowGraphNodeLines(m_object, &count);

	vector<DisassemblyTextLine> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		DisassemblyTextLine line;
		line.addr = lines[i].addr;
		line.instrIndex = lines[i].instrIndex;
		line.highlight = lines[i].highlight;
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
	m_cachedLines = result;
	m_cachedLinesValid = true;
	return m_cachedLines;
}


void FlowGraphNode::SetLines(const vector<DisassemblyTextLine>& lines)
{
	BNDisassemblyTextLine* buf = new BNDisassemblyTextLine[lines.size()];
	for (size_t i = 0; i < lines.size(); i++)
	{
		const DisassemblyTextLine& line = lines[i];
		buf[i].addr = line.addr;
		buf[i].instrIndex = line.instrIndex;
		buf[i].highlight = line.highlight;
		buf[i].tokens = new BNInstructionTextToken[line.tokens.size()];
		buf[i].count = line.tokens.size();
		for (size_t j = 0; j < line.tokens.size(); j++)
		{
			const InstructionTextToken& token = line.tokens[j];
			buf[i].tokens[j].type = token.type;
			buf[i].tokens[j].text = BNAllocString(token.text.c_str());
			buf[i].tokens[j].value = token.value;
			buf[i].tokens[j].size = token.size;
			buf[i].tokens[j].operand = token.operand;
			buf[i].tokens[j].context = token.context;
			buf[i].tokens[j].confidence = token.confidence;
			buf[i].tokens[j].address = token.address;
		}
	}

	BNSetFlowGraphNodeLines(m_object, buf, lines.size());

	for (size_t i = 0; i < lines.size(); i++)
	{
		for (size_t j = 0; j < buf[i].count; j++)
			BNFreeString(buf[i].tokens[j].text);
		delete[] buf[i].tokens;
	}
	delete[] buf;

	m_cachedLines = lines;
	m_cachedLinesValid = true;
}


const vector<FlowGraphEdge>& FlowGraphNode::GetOutgoingEdges()
{
	if (m_cachedEdgesValid)
		return m_cachedEdges;

	size_t count;
	BNFlowGraphEdge* edges = BNGetFlowGraphNodeOutgoingEdges(m_object, &count);

	vector<FlowGraphEdge> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		FlowGraphEdge edge;
		edge.type = edges[i].type;
		edge.target = edges[i].target ? new FlowGraphNode(BNNewFlowGraphNodeReference(edges[i].target)) : nullptr;
		edge.points.insert(edge.points.begin(), &edges[i].points[0], &edges[i].points[edges[i].pointCount]);
		edge.backEdge = edges[i].backEdge;
		result.push_back(edge);
	}

	BNFreeFlowGraphNodeOutgoingEdgeList(edges, count);
	m_cachedEdges = result;
	m_cachedEdgesValid = true;
	return m_cachedEdges;
}


void FlowGraphNode::AddOutgoingEdge(BNBranchType type, FlowGraphNode* target)
{
	BNAddFlowGraphNodeOutgoingEdge(m_object, type, target->GetObject());
	m_cachedEdges.clear();
	m_cachedEdgesValid = false;
}


BNHighlightColor FlowGraphNode::GetHighlight() const
{
	return BNGetFlowGraphNodeHighlight(m_object);
}


void FlowGraphNode::SetHighlight(const BNHighlightColor& color)
{
	BNSetFlowGraphNodeHighlight(m_object, color);
}
