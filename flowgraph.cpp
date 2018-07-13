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


FlowGraph::FlowGraph()
{
	BNCustomFlowGraph callbacks;
	callbacks.context = this;
	callbacks.prepareForLayout = PrepareForLayoutCallback;
	callbacks.populateNodes = PopulateNodesCallback;
	callbacks.completeLayout = CompleteLayoutCallback;
	m_graph = BNCreateCustomFlowGraph(&callbacks);
}


FlowGraph::FlowGraph(BNFlowGraph* graph): m_graph(graph)
{
}


FlowGraph::~FlowGraph()
{
	// This object is going away, so ensure that any pending completion routines are
	// no longer called
	Abort();

	BNFreeFlowGraph(m_graph);
}


void FlowGraph::CompleteCallback(void* ctxt)
{
	FlowGraph* graph = (FlowGraph*)ctxt;
	graph->m_completeFunc();
}


void FlowGraph::PrepareForLayoutCallback(void* ctxt)
{
	FlowGraph* graph = (FlowGraph*)ctxt;
	graph->PrepareForLayout();
}


void FlowGraph::PopulateNodesCallback(void* ctxt)
{
	FlowGraph* graph = (FlowGraph*)ctxt;
	graph->PopulateNodes();
}


void FlowGraph::CompleteLayoutCallback(void* ctxt)
{
	FlowGraph* graph = (FlowGraph*)ctxt;
	graph->CompleteLayout();
}


BNFlowGraph* FlowGraph::UpdateCallback(void* ctxt)
{
	FlowGraph* graph = (FlowGraph*)ctxt;
	Ref<FlowGraph> result = graph->Update();
	if (!result)
		return nullptr;
	return BNNewFlowGraphReference(result->GetGraphObject());
}


void FlowGraph::FinishPrepareForLayout()
{
	BNFinishPrepareForLayout(m_graph);
}


void FlowGraph::PrepareForLayout()
{
	FinishPrepareForLayout();
}


void FlowGraph::PopulateNodes()
{
}


void FlowGraph::CompleteLayout()
{
}


Ref<Function> FlowGraph::GetFunction() const
{
	BNFunction* func = BNGetFunctionForFlowGraph(m_graph);
	if (!func)
		return nullptr;
	return new Function(BNNewFunctionReference(func));
}


void FlowGraph::SetFunction(Function* func)
{
	BNSetFunctionForFlowGraph(m_graph, func ? func->GetObject() : nullptr);
}


int FlowGraph::GetHorizontalNodeMargin() const
{
	return BNGetHorizontalFlowGraphNodeMargin(m_graph);
}


int FlowGraph::GetVerticalNodeMargin() const
{
	return BNGetVerticalFlowGraphNodeMargin(m_graph);
}


void FlowGraph::SetNodeMargins(int horiz, int vert)
{
	BNSetFlowGraphNodeMargins(m_graph, horiz, vert);
}


void FlowGraph::StartLayout()
{
	BNStartFlowGraphLayout(m_graph);
}


bool FlowGraph::IsLayoutComplete()
{
	return BNIsFlowGraphLayoutComplete(m_graph);
}


void FlowGraph::OnComplete(const std::function<void()>& func)
{
	m_completeFunc = func;
	BNSetFlowGraphCompleteCallback(m_graph, this, CompleteCallback);
}


void FlowGraph::Abort()
{
	// Must clear the callback with the core before clearing our own function object, as until it
	// is cleared in the core it can be called at any time from a different thread.
	BNAbortFlowGraph(m_graph);
	m_completeFunc = []() {};
}


vector<Ref<FlowGraphNode>> FlowGraph::GetNodes()
{
	size_t count;
	BNFlowGraphNode** nodes = BNGetFlowGraphNodes(m_graph, &count);

	vector<Ref<FlowGraphNode>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		auto node = m_cachedNodes.find(nodes[i]);
		if (node == m_cachedNodes.end())
		{
			FlowGraphNode* newNode = new FlowGraphNode(BNNewFlowGraphNodeReference(nodes[i]));
			m_cachedNodes[nodes[i]] = newNode;
			result.push_back(newNode);
		}
		else
		{
			result.push_back(node->second);
		}
	}

	BNFreeFlowGraphNodeList(nodes, count);
	return result;
}


Ref<FlowGraphNode> FlowGraph::GetNode(size_t i)
{
	BNFlowGraphNode* node = BNGetFlowGraphNode(m_graph, i);
	if (!node)
		return nullptr;

	auto nodeIter = m_cachedNodes.find(node);
	if (nodeIter == m_cachedNodes.end())
	{
		FlowGraphNode* newNode = new FlowGraphNode(node);
		m_cachedNodes[node] = newNode;
		return newNode;
	}
	else
	{
		BNFreeFlowGraphNode(node);
		return nodeIter->second;
	}
}


bool FlowGraph::HasNodes() const
{
	return BNFlowGraphHasNodes(m_graph);
}


size_t FlowGraph::AddNode(FlowGraphNode* node)
{
	m_cachedNodes[node->GetObject()] = node;
	return BNAddFlowGraphNode(m_graph, node->GetObject());
}


int FlowGraph::GetWidth() const
{
	return BNGetFlowGraphWidth(m_graph);
}


int FlowGraph::GetHeight() const
{
	return BNGetFlowGraphHeight(m_graph);
}


vector<Ref<FlowGraphNode>> FlowGraph::GetNodesInRegion(int left, int top, int right, int bottom)
{
	size_t count;
	BNFlowGraphNode** nodes = BNGetFlowGraphNodesInRegion(m_graph, left, top, right, bottom, &count);

	vector<Ref<FlowGraphNode>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		auto node = m_cachedNodes.find(nodes[i]);
		if (node == m_cachedNodes.end())
		{
			FlowGraphNode* newNode = new FlowGraphNode(BNNewFlowGraphNodeReference(nodes[i]));
			m_cachedNodes[nodes[i]] = newNode;
			result.push_back(newNode);
		}
		else
		{
			result.push_back(node->second);
		}
	}

	BNFreeFlowGraphNodeList(nodes, count);
	return result;
}


bool FlowGraph::IsILGraph() const
{
	return BNIsILFlowGraph(m_graph);
}


bool FlowGraph::IsLowLevelILGraph() const
{
	return BNIsLowLevelILFlowGraph(m_graph);
}


bool FlowGraph::IsMediumLevelILGraph() const
{
	return BNIsMediumLevelILFlowGraph(m_graph);
}


Ref<LowLevelILFunction> FlowGraph::GetLowLevelILFunction() const
{
	BNLowLevelILFunction* func = BNGetFlowGraphLowLevelILFunction(m_graph);
	if (!func)
		return nullptr;
	return new LowLevelILFunction(func);
}


Ref<MediumLevelILFunction> FlowGraph::GetMediumLevelILFunction() const
{
	BNMediumLevelILFunction* func = BNGetFlowGraphMediumLevelILFunction(m_graph);
	if (!func)
		return nullptr;
	return new MediumLevelILFunction(func);
}


void FlowGraph::SetLowLevelILFunction(LowLevelILFunction* func)
{
	BNSetFlowGraphLowLevelILFunction(m_graph, func ? func->GetObject() : nullptr);
}


void FlowGraph::SetMediumLevelILFunction(MediumLevelILFunction* func)
{
	BNSetFlowGraphMediumLevelILFunction(m_graph, func ? func->GetObject() : nullptr);
}


void FlowGraph::Show(const string& title)
{
	ShowGraphReport(title, this);
}


Ref<FlowGraph> FlowGraph::Update()
{
	return nullptr;
}


CoreFlowGraph::CoreFlowGraph(BNFlowGraph* graph): FlowGraph(graph)
{
}


Ref<FlowGraph> CoreFlowGraph::Update()
{
	BNFlowGraph* graph = BNUpdateFlowGraph(GetGraphObject());
	if (!graph)
		return nullptr;
	return new CoreFlowGraph(graph);
}
