#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


FunctionGraph::FunctionGraph(BNFunctionGraph* graph): m_graph(graph)
{
}


FunctionGraph::~FunctionGraph()
{
	BNFreeFunctionGraph(m_graph);
}


void FunctionGraph::CompleteCallback(void* ctxt)
{
	FunctionGraph* graph = (FunctionGraph*)ctxt;
	graph->m_completeFunc();
}


Ref<Function> FunctionGraph::GetFunction() const
{
	return new Function(BNNewFunctionReference(BNGetFunctionForFunctionGraph(m_graph)));
}


int FunctionGraph::GetHorizontalBlockMargin() const
{
	return BNGetHorizontalFunctionGraphBlockMargin(m_graph);
}


int FunctionGraph::GetVerticalBlockMargin() const
{
	return BNGetVerticalFunctionGraphBlockMargin(m_graph);
}


void FunctionGraph::SetBlockMargins(int horiz, int vert)
{
	BNSetFunctionGraphBlockMargins(m_graph, horiz, vert);
}


void FunctionGraph::StartLayout()
{
	BNStartFunctionGraphLayout(m_graph);
}


bool FunctionGraph::IsLayoutComplete()
{
	return BNIsFunctionGraphLayoutComplete(m_graph);
}


void FunctionGraph::OnComplete(const std::function<void()>& func)
{
	m_completeFunc = func;
	BNSetFunctionGraphCompleteCallback(m_graph, this, CompleteCallback);
}


vector<Ref<FunctionGraphBlock>> FunctionGraph::GetBlocks() const
{
	size_t count;
	BNFunctionGraphBlock** blocks = BNGetFunctionGraphBlocks(m_graph, &count);

	vector<Ref<FunctionGraphBlock>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new FunctionGraphBlock(BNNewFunctionGraphBlockReference(blocks[i])));

	BNFreeFunctionGraphBlockList(blocks, count);
	return result;
}


int FunctionGraph::GetLeftExtent() const
{
	return BNGetFunctionGraphLeftExtent(m_graph);
}


int FunctionGraph::GetTopExtent() const
{
	return BNGetFunctionGraphTopExtent(m_graph);
}


int FunctionGraph::GetRightExtent() const
{
	return BNGetFunctionGraphRightExtent(m_graph);
}


int FunctionGraph::GetBottomExtent() const
{
	return BNGetFunctionGraphBottomExtent(m_graph);
}


vector<Ref<FunctionGraphBlock>> FunctionGraph::GetBlocksInRegion(int left, int top, int right, int bottom)
{
	size_t count;
	BNFunctionGraphBlock** blocks = BNGetFunctionGraphBlocksInRegion(m_graph, left, top, right, bottom, &count);

	vector<Ref<FunctionGraphBlock>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new FunctionGraphBlock(BNNewFunctionGraphBlockReference(blocks[i])));

	BNFreeFunctionGraphBlockList(blocks, count);
	return result;
}
