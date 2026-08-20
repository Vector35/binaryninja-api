// MIT License
// 
// Copyright (c) 2015-2024 Vector 35 Inc
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.


#include "binaryninjaapi.h"
#include "mediumlevelilinstruction.h"

/*
	This workflow reverses the control-flow flattening algorithm of Limoncello[1],
	at least some of the time. It does this in a relatively simple manner:

	1. Find "dispatcher blocks" which contain a MLIL_JUMP_TO whose targets all have the
	   dispatcher as a post-dominator (ie all targets must flow back to the dispatcher)
	2. Walk backwards from all unconditional branches into the dispatcher until finding blocks
	   with conditional branches and build a list of all unconditional continuation blocks
	   for each block that flows into the dispatcher.
	3. Copy those continuation blocks and the dispatcher into each block that calls them.
	   This leaves you with a copy of the dispatcher block (and intermediate bookkeeping) in
	   every path that would have normally flowed into the dispatcher.
	4. Since each path now has its own copy of the dispatcher, use MLIL dataflow to solve for
	   which branch of the dispatcher is taken at each copy. When a dispatcher with a solved
	   target is encountered, rewrite it as an MLIL_GOTO with the target directly.

	[1] https://github.com/jonpalmisc/limoncello
 */

using namespace BinaryNinja;

/*!
 * Determine if a block looks like a CFF dispatcher, i.e. all outgoing edges
 * post-dominate it (or return)
 * @param block The block to check
 * @return True if it's a dispatcher
 */
bool IsDispatcher(Ref<BasicBlock> block)
{
	for (auto i = block->GetStart(); i < block->GetEnd(); i++)
	{
		auto ins = block->GetMediumLevelILFunction()->GetInstruction(i);
		if (ins.operation == MLIL_JUMP_TO)
		{
			for (auto& edge: block->GetOutgoingEdges())
			{
				auto outBlock = edge.target;
				// This is too trivial for fancier cases with multiple blocks that all lead
				// to a return, but whatever this is just a sample plugin
				if (outBlock->GetOutgoingEdges().empty())
				{
					continue;
				}
				auto postDominators = outBlock->GetDominators(true);
				if (postDominators.find(block) == postDominators.end())
				{
					return false;
				}
			}
			return true;
		}
	}
	return false;
}


Ref<FlowGraph> GraphPls(Ref<MediumLevelILFunction> fn)
{
	// For ReportCollection, create graph with the settings I want
	Ref<DisassemblySettings> settings = new DisassemblySettings();
	settings->SetOption(ShowAddress, true);
	return fn->CreateFunctionGraphImmediate(settings);
}


BNHighlightColor GetHighlightColor(BNHighlightStandardColor color)
{
	BNHighlightColor highlight;
	highlight.style = StandardHighlightColor;
	highlight.color = color;
	highlight.mixColor = NoHighlightColor;
	highlight.mix = 0;
	highlight.r = 0;
	highlight.g = 0;
	highlight.b = 0;
	highlight.alpha = 255;
	return highlight;
}


void RewriteAction(Ref<AnalysisContext> context, bool doIt)
{
	// Main workflow action

	// ==================================================================================
	// Custom debug report

	Ref<ReportCollection> report;
	if (context->GetFunction()->CheckForDebugReport("unflatten"))
	{
		report = new ReportCollection();
	}

	try
	{
		[&]()
		{
			if (report)
			{
				auto graph = GraphPls(context->GetMediumLevelILFunction());
				report->AddGraphReport(context->GetBinaryView(), "Initial", graph);
			}

			// ==============================================================================
			// Finding flattened control flow and resolving continuations

			// Look for dispatcher block
			Ref<BasicBlock> dispatcher;
			for (auto block: context->GetMediumLevelILFunction()->GetBasicBlocks())
			{
				if (IsDispatcher(block))
				{
					dispatcher = block;
					break;
				}
			}
			if (!dispatcher)
			{
				return;
			}

			if (report)
			{
				auto graph = GraphPls(context->GetMediumLevelILFunction());
				auto nodes = graph->GetNodes();
				for (size_t i = 0; i < nodes.size(); i++)
				{
					auto node = nodes[i];
					if (node->GetBasicBlock()->GetStart() == dispatcher->GetStart())
					{
						node->SetHighlight(GetHighlightColor(RedHighlightColor));
					}
					graph->ReplaceNode(i, node);
				}
				report->AddGraphReport(context->GetBinaryView(), "Finding Dispatcher", graph);
			}

			// Find blocks that flow directly into the dispatcher
			std::deque<Ref<BasicBlock>> queue;
			std::map<Ref<BasicBlock>, std::deque<Ref<BasicBlock>>> toCopy;
			for (auto& incoming: dispatcher->GetIncomingEdges())
			{
				auto dominators = incoming.target->GetDominators(true);
				if (dominators.find(dispatcher) != dominators.end())
				{
					toCopy[incoming.target] = {dispatcher};
					queue.push_back(incoming.target);
				}
			}

			// For each of these, walk back along unconditional branch edges to find their
			// list of continuation blocks which will be copied at their end
			while (!queue.empty())
			{
				// This is sorf of a backwards BFS
				auto top = queue.front();
				queue.pop_front();
				bool anyConditional = false;
				for (auto& incoming: top->GetIncomingEdges())
				{
					if (incoming.type != UnconditionalBranch)
					{
						anyConditional = true;
					}
				}
				// Having any conditional branches ends the unconditional chain
				if (!anyConditional)
				{
					for (auto& incoming: top->GetIncomingEdges())
					{
						if (incoming.type == UnconditionalBranch)
						{
							if (toCopy.find(incoming.target) == toCopy.end())
							{
								queue.push_back(incoming.target);
							}
							toCopy[incoming.target] = toCopy[top];
							toCopy[incoming.target].push_front(top);
						}
					}
					toCopy[top] = {};
				}
			}

			// Ignore empty continuation paths
			std::vector<Ref<BasicBlock>> toPrune;
			for (auto& [bb, path]: toCopy)
			{
				if (path.empty())
				{
					toPrune.push_back(bb);
				}
			}
			for (auto& bb: toPrune)
			{
				toCopy.erase(bb);
			}

			if (report)
			{
				for (auto& [bb, path]: toCopy)
				{
					auto graph = GraphPls(context->GetMediumLevelILFunction());
					auto nodes = graph->GetNodes();
					for (size_t i = 0; i < nodes.size(); i++)
					{
						auto node = nodes[i];
						if (node->GetBasicBlock()->GetStart() == bb->GetStart())
						{
							node->SetHighlight(GetHighlightColor(RedHighlightColor));
						}
						else if (std::find_if(path.begin(), path.end(), [node](const Ref<BasicBlock>& b) { return b->GetStart() == node->GetBasicBlock()->GetStart(); }) != path.end())
						{
							node->SetHighlight(GetHighlightColor(GreenHighlightColor));
						}
						graph->ReplaceNode(i, node);
					}
					report->AddGraphReport(context->GetBinaryView(), "  Blocks flowing into", graph);
				}
			}

			// ==========================================================================
			// Modify the IL to copy the continuations into all the blocks calling the dispatcher

			auto oldMLIL = context->GetMediumLevelILFunction();
			Ref<MediumLevelILFunction> newMLIL = new MediumLevelILFunction(oldMLIL->GetArchitecture(), oldMLIL->GetFunction(), context->GetLowLevelILFunction());
			newMLIL->PrepareToCopyFunction(oldMLIL);
			std::map<Ref<BasicBlock>, size_t> blockMapStarts;

			// Copy all instructions in all blocks of the old version of the function
			for (auto& block: oldMLIL->GetBasicBlocks())
			{
				newMLIL->PrepareToCopyBlock(block);
				blockMapStarts[block] = newMLIL->GetInstructionCount();

				newMLIL->SetCurrentAddress(block->GetArchitecture(), oldMLIL->GetInstruction(block->GetStart()).address);
				for (size_t instrIndex = block->GetStart(); instrIndex < block->GetEnd(); instrIndex++)
				{
					auto oldInstr = oldMLIL->GetInstruction(instrIndex);

					// Copy continuation blocks to end of block calling dispatcher
					if (toCopy.find(block) != toCopy.end())
					{
						if (instrIndex == block->GetEnd() - 1)
						{
							// For every block in the continuation, copy it at the end of this block
							for (auto& copyBlock: toCopy[block])
							{
								newMLIL->PrepareToCopyBlock(copyBlock);

								// Skip the final instruction in the continuations because it is a MLIL_GOTO
								size_t end = copyBlock->GetEnd() - 1;
								if (copyBlock == dispatcher)
								{
									end = copyBlock->GetEnd();
								}

								for (size_t copyBlockInstrIndex = copyBlock->GetStart(); copyBlockInstrIndex < end; copyBlockInstrIndex++)
								{
									// Copy instruction as-is
									auto copyBlockInstr = oldMLIL->GetInstruction(copyBlockInstrIndex);
									newMLIL->SetCurrentAddress(copyBlock->GetArchitecture(), copyBlockInstr.address);
									newMLIL->AddInstruction(copyBlockInstr.CopyTo(newMLIL), copyBlockInstr);
								}
							}
							continue;
						}
					}

					// Otherwise, copy the instruction as-is
					newMLIL->SetCurrentAddress(block->GetArchitecture(), oldInstr.address);
					newMLIL->AddInstruction(oldInstr.CopyTo(newMLIL), oldInstr);
				}
			}

			// Generate blocks and SSA (for dataflow) for the next part
			newMLIL->Finalize();
			newMLIL->GenerateSSAForm();

			// Since we're constructing a new function twice, we need to commit the mappings
			// of the intermediate function before copying again so that mappings will resolve
			// all the way to the end (gross)
			// TODO: Construct from another function without needing this
			context->SetMediumLevelILFunction(newMLIL);

			if (report)
			{
				auto graph = GraphPls(context->GetMediumLevelILFunction());
				report->AddGraphReport(context->GetBinaryView(), "Swapped dispatch with jump_to", graph);
			}

			// ==========================================================================
			// Now convert all MLIL_JUMP_TO with a known dest to a jump

			// Maybe this should be a separate workflow action (so it can be composed)
			oldMLIL = newMLIL;
			newMLIL = new MediumLevelILFunction(oldMLIL->GetArchitecture(), oldMLIL->GetFunction(), context->GetLowLevelILFunction());
			newMLIL->PrepareToCopyFunction(oldMLIL);

			for (auto& block: oldMLIL->GetBasicBlocks())
			{
				newMLIL->PrepareToCopyBlock(block);

				for (size_t instrIndex = block->GetStart(); instrIndex < block->GetEnd(); instrIndex++)
				{
					auto oldInstr = oldMLIL->GetInstruction(instrIndex);
					newMLIL->SetCurrentAddress(block->GetArchitecture(), oldInstr.address);

					// If we find a MLIL_JUMP_TO with a known constant dest, then rewrite it
					// to a MLIL_GOTO with the known dest filled in
					if (oldInstr.operation == MLIL_JUMP_TO)
					{
						if (oldInstr.GetDestExpr<MLIL_JUMP_TO>().GetValue().state == ConstantPointerValue)
						{
							size_t destValue = oldInstr.GetDestExpr<MLIL_JUMP_TO>().GetValue().value;
							auto targets = oldInstr.GetTargets<MLIL_JUMP_TO>();
							if (std::find_if(targets.begin(), targets.end(), [&](const std::pair<size_t, size_t>& target) {
								return target.first == destValue;
							}) != targets.end()) {
								auto oldTargetIndex = targets[destValue];
								BNMediumLevelILLabel* targetLabel = newMLIL->GetLabelForSourceInstruction(oldTargetIndex);
								newMLIL->AddInstruction(newMLIL->Goto(*targetLabel, oldInstr), oldInstr);
								continue;
							}
						}
					}

					// Otherwise, copy the instruction as-is
					newMLIL->AddInstruction(oldInstr.CopyTo(newMLIL), oldInstr);
				}
			}

			newMLIL->Finalize();
			newMLIL->GenerateSSAForm();

			if (report)
			{
				auto graph = GraphPls(context->GetMediumLevelILFunction());
				report->AddGraphReport(context->GetBinaryView(), "Resolved constant jump_to's", graph);
			}

			// ==========================================================================
			// And we're done

			if (doIt)
			{
				context->SetMediumLevelILFunction(newMLIL);
			}
		}();
		// Show debug report if requested, even on exception thrown
		if (report)
		{
			ShowReportCollection("Unflatten Debug Report", report);
		}
	}
	catch (...)
	{
		// Show debug report if requested, even on exception thrown
		if (report)
		{
			ShowReportCollection("Unflatten Debug Report", report);
		}
	}
}


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		auto wf = Workflow::Get("core.function.metaAnalysis")->Clone("core.function.metaAnalysis");
		wf->RegisterActivity(new Activity(R"~(
				{
					"name": "extension.unflatten_limoncello_cpp.unflatten.dry_run",
					"title": "Unflatten (Limoncello C++) Dry Run",
					"description": "Detect and reverse Limoncello's Control Flow Flattening scheme.",
					"eligibility": {
						"auto": {
							"default": false
						}
					}
				}
			)~",
			[](Ref<AnalysisContext> context) {
				RewriteAction(context, false);
			}));
		wf->RegisterActivity(new Activity(R"~(
				{
					"name": "extension.unflatten_limoncello_cpp.unflatten",
					"title": "Unflatten (Limoncello C++)",
					"description": "Detect and reverse Limoncello's Control Flow Flattening scheme.",
					"eligibility": {
						"auto": {
							"default": false
						}
					}
				}
			)~",
			[](Ref<AnalysisContext> context) {
				RewriteAction(context, true);
			}));
		wf->InsertAfter("core.function.generateMediumLevelIL", std::vector<std::string>{
			"extension.unflatten_limoncello_cpp.unflatten.dry_run",
			"extension.unflatten_limoncello_cpp.unflatten"
		});
		Workflow::RegisterWorkflow(wf);
		return true;
	}

	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
	}
}
