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

std::unordered_map<BNRenderLayer*, RenderLayer*> RenderLayer::g_registeredInstances;


RenderLayer::RenderLayer(const std::string& name): m_nameForRegister(name)
{

}


RenderLayer::RenderLayer(BNRenderLayer* layer)
{
	m_object = layer;
}


void RenderLayer::ApplyToFlowGraphCallback(void* ctxt, BNFlowGraph* graph)
{
	RenderLayer* layer = (RenderLayer*)ctxt;
	layer->ApplyToFlowGraph(new CoreFlowGraph(BNNewFlowGraphReference(graph)));
}


void RenderLayer::ApplyToLinearViewObjectCallback(
	void* ctxt,
	BNLinearViewObject* obj,
	BNLinearViewObject* prev,
	BNLinearViewObject* next,
	BNLinearDisassemblyLine* inLines,
	size_t inLineCount,
	BNLinearDisassemblyLine** outLines,
	size_t* outLineCount
)
{
	RenderLayer* layer = (RenderLayer*)ctxt;
	vector<LinearDisassemblyLine> lines = ParseAPIObjectList<LinearDisassemblyLine>(inLines, inLineCount);

	layer->ApplyToLinearViewObject(
		new LinearViewObject(BNNewLinearViewObjectReference(obj)),
		prev ? new LinearViewObject(BNNewLinearViewObjectReference(prev)) : nullptr,
		next ? new LinearViewObject(BNNewLinearViewObjectReference(next)) : nullptr,
		lines
	);

	AllocAPIObjectList<LinearDisassemblyLine>(lines, outLines, outLineCount);
}


void RenderLayer::FreeLinesCallback(void* ctxt, BNLinearDisassemblyLine* lines, size_t count)
{
	FreeAPIObjectList<LinearDisassemblyLine>(lines, count);
}


void RenderLayer::Register(RenderLayer* layer, BNRenderLayerDefaultEnableState enableState)
{
	BNRenderLayerCallbacks cb;
	cb.context = (void*)layer;
	cb.applyToFlowGraph = ApplyToFlowGraphCallback;
	cb.applyToLinearViewObject = ApplyToLinearViewObjectCallback;
	cb.freeLines = FreeLinesCallback;
	layer->m_object = BNRegisterRenderLayer(layer->m_nameForRegister.c_str(), &cb, enableState);
	g_registeredInstances[layer->m_object] = layer;
}


std::vector<Ref<RenderLayer>> RenderLayer::GetList()
{
	size_t count;
	BNRenderLayer** list = BNGetRenderLayerList(&count);
	vector<Ref<RenderLayer>> result;
	for (size_t i = 0; i < count; i ++)
	{
		if (auto reg = g_registeredInstances.find(list[i]); reg != g_registeredInstances.end())
		{
			result.push_back(reg->second);
		}
		else
		{
			result.push_back(new CoreRenderLayer(list[i]));
		}
	}
	BNFreeRenderLayerList(list);
	return result;
}


Ref<RenderLayer> RenderLayer::GetByName(const std::string& name)
{
	BNRenderLayer* result = BNGetRenderLayerByName(name.c_str());
	if (!result)
		return nullptr;
	if (auto reg = g_registeredInstances.find(result); reg != g_registeredInstances.end())
	{
		return reg->second;
	}
	return new CoreRenderLayer(result);
}


BNRenderLayerDefaultEnableState RenderLayer::GetDefaultEnableState() const
{
	return BNGetRenderLayerDefaultEnableState(m_object);
}


std::string RenderLayer::GetName() const
{
	char* name = BNGetRenderLayerName(m_object);
	std::string value = name;
	BNFreeString(name);
	return value;
}


void RenderLayer::ApplyToBlock(
	Ref<BasicBlock> block,
	std::vector<DisassemblyTextLine>& lines
)
{
	if (!block->IsILBlock())
	{
		ApplyToDisassemblyBlock(block, lines);
	}
	else if (block->IsLowLevelILBlock())
	{
		ApplyToLowLevelILBlock(block, lines);
	}
	else if (block->IsMediumLevelILBlock())
	{
		ApplyToMediumLevelILBlock(block, lines);
	}
	else if (block->IsHighLevelILBlock())
	{
		ApplyToHighLevelILBlock(block, lines);
	}
}


void RenderLayer::ApplyToFlowGraph(Ref<FlowGraph> graph)
{
	for (auto node: graph->GetNodes())
	{
		auto lines = node->GetLines();
		if (node->GetBasicBlock())
		{
			ApplyToBlock(node->GetBasicBlock(), lines);
		}
		node->SetLines(lines);
	}
}


void RenderLayer::ApplyToLinearViewObject(
	Ref<LinearViewObject> obj,
	Ref<LinearViewObject> prev,
	Ref<LinearViewObject> next,
	std::vector<LinearDisassemblyLine>& lines
)
{
	// Hack: HLIL bodies don't have basic blocks
	if (!lines.empty() &&
		(obj->GetIdentifier().name == "HLIL Function Body"
		|| obj->GetIdentifier().name == "HLIL SSA Function Body"
		|| obj->GetIdentifier().name == "Language Representation Function Body"))
	{
		ApplyToHighLevelILBody(lines[0].function, lines);
		return;
	}

	std::vector<LinearDisassemblyLine> blockLines;
	std::vector<LinearDisassemblyLine> finalLines;
	Ref<BasicBlock> lastBlock;

	auto finishBlock = [&]()
	{
		if (!blockLines.empty())
		{
			if (lastBlock)
			{
				// Convert linear lines to disassembly lines for the apply()
				// and then convert back for linear view
				std::vector<LinearDisassemblyLine> newBlockLines;
				std::vector<DisassemblyTextLine> disasmLines;
				std::vector<LinearDisassemblyLine> miscLines;

				auto processDisasm = [&]()
				{
					if (!disasmLines.empty())
					{
						ApplyToBlock(lastBlock, disasmLines);
						Ref<Function> func = blockLines[0].function;
						Ref<BasicBlock> block = blockLines[0].block;
						for (auto& blockLine: disasmLines)
						{
							LinearDisassemblyLine newLine;
							newLine.type = CodeDisassemblyLineType;
							newLine.function = func;
							newLine.block = block;
							newLine.contents = blockLine;
							newBlockLines.push_back(newLine);
						}
						disasmLines.clear();
					}
				};

				auto processMisc = [&]()
				{
					if (!miscLines.empty())
					{
						ApplyToMiscLinearLines(obj, prev, next, miscLines);
						std::move(
							miscLines.begin(),
							miscLines.end(),
							std::back_inserter(newBlockLines)
						);
						miscLines.clear();
					}
				};

				for (auto& blockLine: blockLines)
				{
					// Lines in the block get sent to processDisasm, anything else goes
					// to processMisc so we preserve line information
					if (blockLine.type == CodeDisassemblyLineType)
					{
						processMisc();
						disasmLines.push_back(blockLine.contents);
					}
					else
					{
						processDisasm();
						miscLines.push_back(blockLine);
					}
				}
				// At the end, zero or one of these has lines in it
				processMisc();
				processDisasm();
				blockLines = newBlockLines;
			}
			else
			{
				ApplyToMiscLinearLines(obj, prev, next, blockLines);
			}
		}
		std::move(blockLines.begin(), blockLines.end(), std::back_inserter(finalLines));
	};

	for (auto& line: lines)
	{
		// Assume we've finished a block when the line's block changes
		if (line.block != lastBlock)
		{
			finishBlock();
		}
		blockLines.push_back(line);
		lastBlock = line.block;
	}
	// And we've finished a block when we're done with every line
	finishBlock();

	lines = finalLines;
}


CoreRenderLayer::CoreRenderLayer(BNRenderLayer* layer): RenderLayer(layer)
{
}


void CoreRenderLayer::ApplyToFlowGraph(Ref<FlowGraph> graph)
{
	BNApplyRenderLayerToFlowGraph(m_object, graph->GetObject());
}


void CoreRenderLayer::ApplyToLinearViewObject(
	Ref<LinearViewObject> obj,
	Ref<LinearViewObject> prev,
	Ref<LinearViewObject> next,
	std::vector<LinearDisassemblyLine>& lines
)
{
	BNLinearDisassemblyLine* inLines;
	size_t inLineCount;
	AllocAPIObjectList<LinearDisassemblyLine>(lines, &inLines, &inLineCount);

	BNLinearDisassemblyLine* outLines;
	size_t outLineCount;

	BNApplyRenderLayerToLinearViewObject(
		m_object,
		obj->GetObject(),
		prev ? prev->GetObject() : nullptr,
		next ? next->GetObject() : nullptr,
		inLines,
		inLineCount,
		&outLines,
		&outLineCount
	);

	lines = ParseAPIObjectList<LinearDisassemblyLine>(outLines, outLineCount);
	FreeAPIObjectList<LinearDisassemblyLine>(inLines, inLineCount);
	BNFreeLinearDisassemblyLines(outLines, outLineCount);
}
