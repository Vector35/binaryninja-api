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


FlowGraphLayoutRequest::FlowGraphLayoutRequest(FlowGraph* graph, const std::function<void()>& completeFunc) :
    m_completeFunc(completeFunc)
{
	m_object = BNStartFlowGraphLayout(graph->GetObject(), this, CompleteCallback);
}


FlowGraphLayoutRequest::~FlowGraphLayoutRequest()
{
	// This object is going away, so ensure that any pending completion routines are
	// no longer called
	Abort();

	BNFreeFlowGraphLayoutRequest(m_object);
}


void FlowGraphLayoutRequest::CompleteCallback(void* ctxt)
{
	FlowGraphLayoutRequest* layout = (FlowGraphLayoutRequest*)ctxt;
	layout->m_completeFunc();
}


Ref<FlowGraph> FlowGraphLayoutRequest::GetGraph() const
{
	return new CoreFlowGraph(BNGetGraphForFlowGraphLayoutRequest(m_object));
}


bool FlowGraphLayoutRequest::IsComplete() const
{
	return BNIsFlowGraphLayoutRequestComplete(m_object);
}


void FlowGraphLayoutRequest::Abort()
{
	// Must clear the callback with the core before clearing our own function object, as until it
	// is cleared in the core it can be called at any time from a different thread.
	BNAbortFlowGraphLayoutRequest(m_object);
	m_completeFunc = []() {
	};
}


FlowGraph::FlowGraph()
{
	BNCustomFlowGraph callbacks;
	callbacks.context = this;
	callbacks.prepareForLayout = PrepareForLayoutCallback;
	callbacks.populateNodes = PopulateNodesCallback;
	callbacks.completeLayout = CompleteLayoutCallback;
	callbacks.update = UpdateCallback;
	callbacks.freeObject = FreeObjectCallback;
	callbacks.externalRefTaken = nullptr;
	callbacks.externalRefReleased = nullptr;
	AddRefForRegistration();
	m_object = BNCreateCustomFlowGraph(&callbacks);
}


FlowGraph::FlowGraph(BNFlowGraph* graph)
{
	m_object = graph;
}


void FlowGraph::PrepareForLayoutCallback(void* ctxt)
{
	CallbackRef<FlowGraph> graph(ctxt);
	graph->PrepareForLayout();
}


void FlowGraph::PopulateNodesCallback(void* ctxt)
{
	CallbackRef<FlowGraph> graph(ctxt);
	graph->PopulateNodes();
}


void FlowGraph::CompleteLayoutCallback(void* ctxt)
{
	CallbackRef<FlowGraph> graph(ctxt);
	graph->CompleteLayout();
}


BNFlowGraph* FlowGraph::UpdateCallback(void* ctxt)
{
	CallbackRef<FlowGraph> graph(ctxt);
	Ref<FlowGraph> result = graph->Update();
	if (!result)
		return nullptr;
	return BNNewFlowGraphReference(result->GetObject());
}


void FlowGraph::FreeObjectCallback(void* ctxt)
{
	FlowGraph* graph = (FlowGraph*)ctxt;
	graph->ReleaseForRegistration();
}


void FlowGraph::FinishPrepareForLayout()
{
	BNFinishPrepareForLayout(m_object);
}


void FlowGraph::PrepareForLayout()
{
	FinishPrepareForLayout();
}


void FlowGraph::PopulateNodes() {}


void FlowGraph::CompleteLayout() {}


Ref<Function> FlowGraph::GetFunction() const
{
	BNFunction* func = BNGetFunctionForFlowGraph(m_object);
	if (!func)
		return nullptr;
	return new Function(func);
}


Ref<BinaryView> FlowGraph::GetView() const
{
	BNBinaryView* view = BNGetViewForFlowGraph(m_object);
	if (!view)
		return nullptr;
	return new BinaryView(view);
}


void FlowGraph::SetFunction(Function* func)
{
	BNSetFunctionForFlowGraph(m_object, func ? func->GetObject() : nullptr);
}


void FlowGraph::SetView(BinaryView* view)
{
	BNSetViewForFlowGraph(m_object, view ? view->GetObject() : nullptr);
}


int FlowGraph::GetHorizontalNodeMargin() const
{
	return BNGetHorizontalFlowGraphNodeMargin(m_object);
}


int FlowGraph::GetVerticalNodeMargin() const
{
	return BNGetVerticalFlowGraphNodeMargin(m_object);
}


void FlowGraph::SetNodeMargins(int horiz, int vert)
{
	BNSetFlowGraphNodeMargins(m_object, horiz, vert);
}


Ref<FlowGraphLayoutRequest> FlowGraph::StartLayout(const std::function<void()>& func)
{
	return new FlowGraphLayoutRequest(this, func);
}


bool FlowGraph::IsLayoutComplete()
{
	return BNIsFlowGraphLayoutComplete(m_object);
}


vector<Ref<FlowGraphNode>> FlowGraph::GetNodes()
{
	size_t count;
	BNFlowGraphNode** nodes = BNGetFlowGraphNodes(m_object, &count);

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
	BNFlowGraphNode* node = BNGetFlowGraphNode(m_object, i);
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


size_t FlowGraph::GetNodeCount() const
{
	return BNGetFlowGraphNodeCount(m_object);
}


bool FlowGraph::HasNodes() const
{
	return BNFlowGraphHasNodes(m_object);
}


size_t FlowGraph::AddNode(FlowGraphNode* node)
{
	m_cachedNodes[node->GetObject()] = node;
	return BNAddFlowGraphNode(m_object, node->GetObject());
}


void FlowGraph::ReplaceNode(size_t i, FlowGraphNode* newNode)
{
	BNReplaceFlowGraphNode(m_object, i, newNode->GetObject());
}


void FlowGraph::ClearNodes()
{
	BNClearFlowGraphNodes(m_object);
}


int FlowGraph::GetWidth() const
{
	return BNGetFlowGraphWidth(m_object);
}


void FlowGraph::SetWidth(int width)
{
	BNFlowGraphSetWidth(m_object, width);
}


int FlowGraph::GetHeight() const
{
	return BNGetFlowGraphHeight(m_object);
}


void FlowGraph::SetHeight(int height)
{
	BNFlowGraphSetHeight(m_object, height);
}


vector<Ref<FlowGraphNode>> FlowGraph::GetNodesInRegion(int left, int top, int right, int bottom)
{
	size_t count;
	BNFlowGraphNode** nodes = BNGetFlowGraphNodesInRegion(m_object, left, top, right, bottom, &count);

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
	return BNIsILFlowGraph(m_object);
}


bool FlowGraph::IsLowLevelILGraph() const
{
	return BNIsLowLevelILFlowGraph(m_object);
}


bool FlowGraph::IsMediumLevelILGraph() const
{
	return BNIsMediumLevelILFlowGraph(m_object);
}


bool FlowGraph::IsHighLevelILGraph() const
{
	return BNIsHighLevelILFlowGraph(m_object);
}


Ref<LowLevelILFunction> FlowGraph::GetLowLevelILFunction() const
{
	BNLowLevelILFunction* func = BNGetFlowGraphLowLevelILFunction(m_object);
	if (!func)
		return nullptr;
	return new LowLevelILFunction(func);
}


Ref<MediumLevelILFunction> FlowGraph::GetMediumLevelILFunction() const
{
	BNMediumLevelILFunction* func = BNGetFlowGraphMediumLevelILFunction(m_object);
	if (!func)
		return nullptr;
	return new MediumLevelILFunction(func);
}


Ref<HighLevelILFunction> FlowGraph::GetHighLevelILFunction() const
{
	BNHighLevelILFunction* func = BNGetFlowGraphHighLevelILFunction(m_object);
	if (!func)
		return nullptr;
	return new HighLevelILFunction(func);
}


void FlowGraph::SetLowLevelILFunction(LowLevelILFunction* func)
{
	BNSetFlowGraphLowLevelILFunction(m_object, func ? func->GetObject() : nullptr);
}


void FlowGraph::SetMediumLevelILFunction(MediumLevelILFunction* func)
{
	BNSetFlowGraphMediumLevelILFunction(m_object, func ? func->GetObject() : nullptr);
}


void FlowGraph::SetHighLevelILFunction(HighLevelILFunction* func)
{
	BNSetFlowGraphHighLevelILFunction(m_object, func ? func->GetObject() : nullptr);
}


void FlowGraph::Show(const string& title)
{
	ShowGraphReport(title, this);
}


bool FlowGraph::HasUpdates() const
{
	return false;
}


Ref<FlowGraph> FlowGraph::Update()
{
	return nullptr;
}


void FlowGraph::SetOption(BNFlowGraphOption option, bool value)
{
	BNSetFlowGraphOption(m_object, option, value);
}


bool FlowGraph::IsOptionSet(BNFlowGraphOption option)
{
	return BNIsFlowGraphOptionSet(m_object, option);
}


std::vector<RenderLayer*> FlowGraph::GetRenderLayers() const
{
	size_t count = 0;
	BNRenderLayer** layers = BNGetFlowGraphRenderLayers(m_object, &count);
	std::vector<RenderLayer*> result;
	for (size_t i = 0; i < count; i ++)
	{
		result.push_back(new CoreRenderLayer(layers[i]));
	}
	BNFreeRenderLayerList(layers);
	return result;
}


void FlowGraph::AddRenderLayer(RenderLayer* layer)
{
	BNAddFlowGraphRenderLayer(m_object, layer->GetObject());
}


void FlowGraph::RemoveRenderLayer(RenderLayer* layer)
{
	BNRemoveFlowGraphRenderLayer(m_object, layer->GetObject());
}


CoreFlowGraph::CoreFlowGraph(BNFlowGraph* graph) : FlowGraph(graph)
{
	m_queryMode = BNFlowGraphUpdateQueryMode(GetObject());
}


bool CoreFlowGraph::HasUpdates() const
{
	if (m_queryMode)
		return BNFlowGraphHasUpdates(GetObject());
	return false;
}


Ref<FlowGraph> CoreFlowGraph::Update()
{
	BNFlowGraph* graph = BNUpdateFlowGraph(GetObject());
	if (!graph)
		return nullptr;
	return new CoreFlowGraph(graph);
}
