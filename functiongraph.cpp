#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


FunctionGraph::FunctionGraph(BNFunctionGraph* graph): m_graph(graph)
{
}


FunctionGraph::~FunctionGraph()
{
	// This object is going away, so ensure that any pending completion routines are
	// no longer called
	Abort();

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


void FunctionGraph::Abort()
{
	// Must clear the callback with the core before clearing our own function object, as until it
	// is cleared in the core it can be called at any time from a different thread.
	BNAbortFunctionGraph(m_graph);
	m_completeFunc = []() {};
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


int FunctionGraph::GetWidth() const
{
	return BNGetFunctionGraphWidth(m_graph);
}


int FunctionGraph::GetHeight() const
{
	return BNGetFunctionGraphHeight(m_graph);
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
