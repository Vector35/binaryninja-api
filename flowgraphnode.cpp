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
#include "ffi.h"

using namespace BinaryNinja;
using namespace std;


FlowGraphNode::FlowGraphNode(FlowGraph* graph)
{
	m_object = BNCreateFlowGraphNode(graph->GetObject());
	m_cachedLinesValid = false;
	m_cachedEdgesValid = false;
	m_cachedIncomingEdgesValid = false;
}


FlowGraphNode::FlowGraphNode(BNFlowGraphNode* node)
{
	m_object = node;
	m_cachedLinesValid = false;
	m_cachedEdgesValid = false;
	m_cachedIncomingEdgesValid = false;
}


Ref<FlowGraph> FlowGraphNode::GetGraph() const
{
	BNFlowGraph* graph = BNGetFlowGraphNodeOwner(m_object);
	if (!graph)
		return nullptr;
	return new CoreFlowGraph(graph);
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


void FlowGraphNode::SetX(int x)
{
	BNFlowGraphNodeSetX(m_object, x);
}


void FlowGraphNode::SetY(int y)
{
	BNFlowGraphNodeSetY(m_object, y);
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

	vector<DisassemblyTextLine> result = ParseAPIObjectList<DisassemblyTextLine>(lines, count);
	BNFreeDisassemblyTextLines(lines, count);
	m_cachedLines = result;
	return m_cachedLines;
}


void FlowGraphNode::SetLines(const vector<DisassemblyTextLine>& lines)
{
	size_t inCount = 0;
	BNDisassemblyTextLine* inLines = AllocAPIObjectList<DisassemblyTextLine>(lines, &inCount);
	BNSetFlowGraphNodeLines(m_object, inLines, inCount);

	FreeAPIObjectList<DisassemblyTextLine>(inLines, inCount);

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
		edge.style.color = edges[i].style.color;
		edge.style.width = edges[i].style.width;
		edge.style.style = edges[i].style.style;
		result.push_back(edge);
	}

	BNFreeFlowGraphNodeEdgeList(edges, count);
	m_cachedEdges = result;
	m_cachedEdgesValid = true;
	return m_cachedEdges;
}


const vector<FlowGraphEdge>& FlowGraphNode::GetIncomingEdges()
{
	if (m_cachedIncomingEdgesValid)
		return m_cachedIncomingEdges;

	size_t count;
	BNFlowGraphEdge* edges = BNGetFlowGraphNodeIncomingEdges(m_object, &count);

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

	BNFreeFlowGraphNodeEdgeList(edges, count);
	m_cachedIncomingEdges = result;
	m_cachedIncomingEdgesValid = true;
	return m_cachedIncomingEdges;
}


void FlowGraphNode::AddOutgoingEdge(BNBranchType type, FlowGraphNode* target, BNEdgeStyle edgeStyle)
{
	BNAddFlowGraphNodeOutgoingEdge(m_object, type, target->GetObject(), edgeStyle);
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


bool FlowGraphNode::IsValidForGraph(FlowGraph* graph) const
{
	return BNIsNodeValidForFlowGraph(graph->GetObject(), m_object);
}


void FlowGraphNode::SetVisibilityRegion(int x, int y, int w, int h)
{
	BNFlowGraphNodeSetVisibilityRegion(m_object, x, y, w, h);
}
