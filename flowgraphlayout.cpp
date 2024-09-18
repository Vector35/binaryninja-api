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


FlowGraphLayout::FlowGraphLayout(BNFlowGraphLayout* layout)
{
	m_object = layout;
}


FlowGraphLayout::FlowGraphLayout(const string& name) : m_nameForRegister(name)
{
	m_object = nullptr;
}


bool FlowGraphLayout::LayoutCallback(void* ctxt, BNFlowGraph* graph, BNFlowGraphNode** nodes, size_t nodeCount)
{
	CallbackRef<FlowGraphLayout> layout(ctxt);
	std::vector<Ref<FlowGraphNode>> nodeVec;
	nodeVec.reserve(nodeCount);

	for (size_t i = 0; i < nodeCount; i++)
	{
		nodeVec.push_back(new FlowGraphNode(nodes[i]));
	}

	bool result = layout->Layout(new CoreFlowGraph(graph), nodeVec);
	return result;
}


void FlowGraphLayout::Register(FlowGraphLayout* layout)
{
	BNCustomFlowGraphLayout callbacks;
	callbacks.context = layout;
	callbacks.layout = LayoutCallback;
	layout->AddRefForRegistration();
	layout->m_object = BNRegisterFlowGraphLayout(layout->m_nameForRegister.c_str(), &callbacks);
}


Ref<FlowGraphLayout> FlowGraphLayout::GetByName(const string& name)
{
	BNFlowGraphLayout* result = BNGetFlowGraphLayoutByName(name.c_str());
	if (!result)
		return nullptr;
	return new CoreFlowGraphLayout(result);
}


vector<Ref<FlowGraphLayout>> FlowGraphLayout::GetFlowGraphLayouts()
{
	size_t count;
	BNFlowGraphLayout** list = BNGetFlowGraphLayouts(&count);

	vector<Ref<FlowGraphLayout>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreFlowGraphLayout(list[i]));

	BNFreeFlowGraphLayoutList(list);
	return result;
}


string FlowGraphLayout::GetName() const
{
	char* name = BNGetFlowGraphLayoutName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}


bool FlowGraphLayout::Layout(Ref<FlowGraph> graph, std::vector<Ref<FlowGraphNode>>& nodes)
{
	return false;
}


CoreFlowGraphLayout::CoreFlowGraphLayout(BNFlowGraphLayout* layout) : FlowGraphLayout(layout) {}


bool CoreFlowGraphLayout::Layout(Ref<FlowGraph> graph, std::vector<Ref<FlowGraphNode>>& nodes)
{
	BNFlowGraphNode** nodeList = new BNFlowGraphNode*[nodes.size()];
	for (size_t i = 0; i < nodes.size(); i++)
	{
		nodeList[i] = nodes[i]->m_object;
	}
	bool result = BNFlowGraphLayoutLayout(m_object, graph->m_object, nodeList, nodes.size());
	delete[] nodeList;
	return result;
}
