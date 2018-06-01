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


Ref<DisassemblySettings> FunctionGraph::GetSettings()
{
	return new DisassemblySettings(BNGetFunctionGraphSettings(m_graph));
}


void FunctionGraph::StartLayout(BNFunctionGraphType type)
{
	BNStartFunctionGraphLayout(m_graph, type);
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


vector<Ref<FunctionGraphBlock>> FunctionGraph::GetBlocks()
{
	size_t count;
	BNFunctionGraphBlock** blocks = BNGetFunctionGraphBlocks(m_graph, &count);

	vector<Ref<FunctionGraphBlock>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		auto block = m_cachedBlocks.find(blocks[i]);
		if (block == m_cachedBlocks.end())
		{
			FunctionGraphBlock* newBlock = new FunctionGraphBlock(BNNewFunctionGraphBlockReference(blocks[i]));
			m_cachedBlocks[blocks[i]] = newBlock;
			result.push_back(newBlock);
		}
		else
		{
			result.push_back(block->second);
		}
	}

	BNFreeFunctionGraphBlockList(blocks, count);
	return result;
}


bool FunctionGraph::HasBlocks() const
{
	return BNFunctionGraphHasBlocks(m_graph);
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
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		auto block = m_cachedBlocks.find(blocks[i]);
		if (block == m_cachedBlocks.end())
		{
			FunctionGraphBlock* newBlock = new FunctionGraphBlock(BNNewFunctionGraphBlockReference(blocks[i]));
			m_cachedBlocks[blocks[i]] = newBlock;
			result.push_back(newBlock);
		}
		else
		{
			result.push_back(block->second);
		}
	}

	BNFreeFunctionGraphBlockList(blocks, count);
	return result;
}


bool FunctionGraph::IsOptionSet(BNDisassemblyOption option) const
{
	return BNIsFunctionGraphOptionSet(m_graph, option);
}


void FunctionGraph::SetOption(BNDisassemblyOption option, bool state)
{
	BNSetFunctionGraphOption(m_graph, option, state);
}


bool FunctionGraph::IsILGraph() const
{
	return BNIsILFunctionGraph(m_graph);
}


bool FunctionGraph::IsLowLevelILGraph() const
{
	return BNIsLowLevelILFunctionGraph(m_graph);
}


bool FunctionGraph::IsMediumLevelILGraph() const
{
	return BNIsMediumLevelILFunctionGraph(m_graph);
}


Ref<LowLevelILFunction> FunctionGraph::GetLowLevelILFunction() const
{
	BNLowLevelILFunction* func = BNGetFunctionGraphLowLevelILFunction(m_graph);
	if (!func)
		return nullptr;
	return new LowLevelILFunction(func);
}


Ref<MediumLevelILFunction> FunctionGraph::GetMediumLevelILFunction() const
{
	BNMediumLevelILFunction* func = BNGetFunctionGraphMediumLevelILFunction(m_graph);
	if (!func)
		return nullptr;
	return new MediumLevelILFunction(func);
}
