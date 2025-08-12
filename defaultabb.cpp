#include <map>
#include <set>
#include <queue>
#include <inttypes.h>
#include "binaryninjaapi.h"
#include "binaryninjacore.h"
#include "lowlevelilinstruction.h"

using namespace std;
using namespace BinaryNinja;

// TODO: Decomposed from BinaryView::IsOffsetCodeSemantics BinaryView::IsOffsetExternSemantics
// TODO: When the better sections model is merged, remove this
static bool IsOffsetCodeSemanticsFast(BinaryView* data, const vector<Section*>& readOnlySections, const vector<Section*>& dataExternSections, uint64_t offset)
{
	if (!data->IsOffsetBackedByFile(offset))
		return false;

	for (const auto& i : readOnlySections)
	{
		if ((offset >= i->GetStart()) && (offset < i->GetEnd()))
			return true;
	}
	for (const auto& i : dataExternSections)
	{
		if ((offset >= i->GetStart()) && (offset < i->GetEnd()))
			return false;
	}

	return data->IsOffsetExecutable(offset);
}


static bool IsOffsetExternSemanticsFast(BinaryView* data, const vector<Section*>& externSections, uint64_t offset)
{
	if (data->IsOffsetBackedByFile(offset))
		return false;
	if (data->IsOffsetExecutable(offset))
		return false;

	for (const auto& i : externSections)
	{
		if ((offset >= i->GetStart()) && (offset < i->GetEnd()))
			return true;
	}

	return false;
}


static bool GetNextFunctionAfterAddress(Ref<BinaryView> data, Ref<Platform> platform, uint64_t address, Ref<Function>& nextFunc)
{
	uint64_t nextFuncAddr = data->GetNextFunctionStartAfterAddress(address);
	nextFunc = data->GetAnalysisFunction(platform, nextFuncAddr);
	return nextFunc != nullptr;
}


void Architecture::DefaultAnalyzeBasicBlocks(Function* function, BasicBlockAnalysisContext& context)
{
	auto data = function->GetView();
	queue<ArchAndAddr> blocksToProcess;
	map<ArchAndAddr, Ref<BasicBlock>> instrBlocks;
	set<ArchAndAddr> seenBlocks;

	bool guidedAnalysisMode = context.GetGuidedAnalysisMode();
	bool triggerGuidedOnInvalidInstruction = context.GetTriggerGuidedOnInvalidInstruction();
	bool translateTailCalls = context.GetTranslateTailCalls();
	bool disallowBranchToString = context.GetDisallowBranchToString();

	auto& indirectBranches = context.GetIndirectBranches();
	auto& indirectNoReturnCalls = context.GetIndirectNoReturnCalls();

	auto& contextualFunctionReturns = context.GetContextualReturns();

	auto& directRefs = context.GetDirectCodeReferences();
	auto& directNoReturnCalls = context.GetDirectNoReturnCalls();
	auto& haltedDisassemblyAddresses = context.GetHaltedDisassemblyAddresses();
	auto& inlinedUnresolvedIndirectBranches = context.GetInlinedUnresolvedIndirectBranches();

	bool hasInvalidInstructions = false;
	set<ArchAndAddr> guidedSourceBlockTargets;
	auto guidedSourceBlocks = function->GetGuidedSourceBlocks();
	set<ArchAndAddr> guidedSourceBlocksSet;
	for (const auto& block : guidedSourceBlocks)
		guidedSourceBlocksSet.insert(block);

	BNStringReference strRef;
	auto targetExceedsByteLimit = [](const BNStringReference& strRef) {
			size_t byteLimit = 8;
			if (strRef.type == Utf16String) byteLimit *= 2;
			else if (strRef.type == Utf32String) byteLimit *= 4;
			return (strRef.length >= byteLimit);
	};

	// TODO: Decomposed from BinaryView::IsOffsetCodeSemantics BinaryView::IsOffsetExternSemantics
	// TODO: When the better sections model is merged, remove this
	auto sections = data->GetSections();
	vector<Section*> externSections, readOnlySections, dataExternSections;
	externSections.reserve(sections.size());
	readOnlySections.reserve(sections.size());
	dataExternSections.reserve(sections.size());
	for (auto& section: sections)
	{
		if (section->GetSemantics() == ExternalSectionSemantics)
		{
			externSections.push_back(section);
		}
		if (section->GetSemantics() == ReadOnlyCodeSectionSemantics)
		{
			readOnlySections.push_back(section);
		}
		if ((section->GetSemantics() == ReadOnlyDataSectionSemantics) ||
			(section->GetSemantics() == ReadWriteDataSectionSemantics) ||
			(section->GetSemantics() == ExternalSectionSemantics))
		{
			dataExternSections.push_back(section);
		}
	}

	// Start by processing the entry point of the function
	Ref<Platform> funcPlatform = function->GetPlatform();
	auto start = function->GetStart();
	blocksToProcess.emplace(funcPlatform->GetArchitecture(), start);
	seenBlocks.emplace(funcPlatform->GetArchitecture(), start);

	// Only validate that branch destinations are executable if the start of the function is executable. This allows
	// data to be disassembled manually
	bool validateExecutable = data->IsOffsetExecutable(start);

	bool fastValidate = false;
	uint64_t fastEndAddr = 0;
	uint64_t fastStartAddr = UINT64_MAX;
	if (validateExecutable)
	{
		// Extract the bounds of the section containing this
		// function, to avoid calling into the BinaryView on
		// every instruction.
		for (auto& sec : data->GetSectionsAt(start))
		{
			if (sec->GetSemantics() == ReadOnlyDataSectionSemantics)
				continue;
			if (sec->GetSemantics() == ReadWriteDataSectionSemantics)
				continue;
			if (!data->IsOffsetBackedByFile(sec->GetStart()))
				continue;
			if (!data->IsOffsetExecutable(sec->GetStart()))
				continue;
			if (fastStartAddr > sec->GetStart())
				fastStartAddr = sec->GetStart();
			if (fastEndAddr < (sec->GetEnd() - 1))
			{
				fastEndAddr = sec->GetEnd() - 1;
				Ref<Segment> segment = data->GetSegmentAt(fastEndAddr);
				if (segment)
					fastEndAddr = (std::min)(fastEndAddr, segment->GetDataEnd() - 1);
			}
			fastValidate = true;
			break;
		}
	}

	uint64_t totalSize = 0;
	uint64_t maxSize = context.GetMaxFunctionSize();
	bool maxSizeReached = false;
	while (blocksToProcess.size() != 0)
	{
		if (data->AnalysisIsAborted())
			return;

		// Get the next block to process
		ArchAndAddr location = blocksToProcess.front();
		ArchAndAddr instructionGroupStart = location;
		blocksToProcess.pop();

		bool isGuidedSourceBlock = guidedSourceBlocksSet.count(location) ? true : false;

		// Create a new basic block
		Ref<BasicBlock> block = context.CreateBasicBlock(location.arch, location.address);

		// Get the next function to prevent disassembling into the next function if the block falls through
		Ref<Function> nextFunc;
		bool hasNextFunc = GetNextFunctionAfterAddress(data, funcPlatform, location.address, nextFunc);
		uint64_t nextFuncAddr = (hasNextFunc && nextFunc) ? nextFunc->GetStart() : 0;
		set<Ref<Function>> calledFunctions;

		// we mostly only case if this is 0, or more than 0. after handling an instruction,
		// we decrement. the architecture can change this value arbitrarily during callbacks.
		uint8_t delaySlotCount = 0;
		bool delayInstructionEndsBlock = false;

		// Disassemble the instructions in the block
		while (true)
		{
			if (data->AnalysisIsAborted())
				return;

			if (!delaySlotCount)
			{
				auto blockIter = instrBlocks.find(location);
				if (blockIter != instrBlocks.end())
				{
					// This instruction has already been seen, go to it directly insread of creating a copy
					Ref<BasicBlock> targetBlock = blockIter->second;
					if (targetBlock->GetStart() == location.address)
					{
						// Instruction is the start of a block, add an unconditional branch to it
						block->AddPendingOutgoingEdge(UnconditionalBranch, location.address, nullptr,
							(block->GetStart() != location.address));
						break;
					}
					else
					{
						// Instruction is in the middle of a block, need to split the basic block into two
						Ref<BasicBlock> splitBlock = context.CreateBasicBlock(location.arch, location.address);
						size_t instrDataLen;
						const uint8_t* instrData = targetBlock->GetInstructionData(location.address, &instrDataLen);
						splitBlock->AddInstructionData(instrData, instrDataLen);
						splitBlock->SetFallThroughToFunction(targetBlock->IsFallThroughToFunction());
						splitBlock->SetUndeterminedOutgoingEdges(targetBlock->HasUndeterminedOutgoingEdges());
						splitBlock->SetCanExit(targetBlock->CanExit());
						splitBlock->SetEnd(targetBlock->GetEnd());

						targetBlock->SetFallThroughToFunction(false);
						targetBlock->SetUndeterminedOutgoingEdges(false);
						targetBlock->SetCanExit(true);
						targetBlock->SetEnd(location.address);

						// Place instructions after the split point into the new block
						for (size_t j = location.address; j < splitBlock->GetEnd(); j++)
						{
							auto k = instrBlocks.find(ArchAndAddr(location.arch, j));
							if ((k != instrBlocks.end()) && (k->second == targetBlock))
								k->second = splitBlock;
						}

						for (auto& k : targetBlock->GetPendingOutgoingEdges())
							splitBlock->AddPendingOutgoingEdge(k.type, k.target, k.arch, k.fallThrough);
						targetBlock->ClearPendingOutgoingEdges();
						targetBlock->AddPendingOutgoingEdge(UnconditionalBranch, location.address, nullptr, true);

						// Mark the new block so that it will not be processed again
						seenBlocks.insert(location);
						context.AddFunctionBasicBlock(splitBlock);

						// Add an outgoing edge from the current block to the new block
						block->AddPendingOutgoingEdge(UnconditionalBranch, location.address);
						break;
					}
				}
			}

			uint8_t opcode[BN_MAX_INSTRUCTION_LENGTH];
			size_t maxLen = data->Read(opcode, location.address, location.arch->GetMaxInstructionLength());
			if (maxLen == 0)
			{
				string text = fmt::format("Could not read instruction at {:#x}", location.address);
				function->CreateAutoAddressTag(location.arch, location.address, "Invalid Instruction", text, true);
				if (location.arch->GetInstructionAlignment() == 0)
					location.address++;
				else
					location.address += location.arch->GetInstructionAlignment();
				block->SetHasInvalidInstructions(true);
				break;
			}

			InstructionInfo info;
			info.delaySlots = delaySlotCount;
			if (!location.arch->GetInstructionInfo(opcode, location.address, maxLen, info))
			{
				string text = fmt::format("Could not get instruction info at {:#x}", location.address);
				function->CreateAutoAddressTag(location.arch, location.address, "Invalid Instruction", text, true);
				if (location.arch->GetInstructionAlignment() == 0)
					location.address++;
				else
					location.address += location.arch->GetInstructionAlignment();
				block->SetHasInvalidInstructions(true);
				break;
			}

			// The instruction is invalid if it has no length or is above maximum length
			if ((info.length == 0) || (info.length > maxLen))
			{
				string text = fmt::format("Instruction of invalid length at {:#x}", location.address);
				function->CreateAutoAddressTag(location.arch, location.address, "Invalid Instruction", text, true);
				if (location.arch->GetInstructionAlignment() == 0)
					location.address++;
				else
					location.address += location.arch->GetInstructionAlignment();
				block->SetHasInvalidInstructions(true);
				break;
			}

			// Instruction is invalid when straddling a boundary to a section that is non-code, or not back by file
			uint64_t instrEnd = location.address + info.length - 1;
			bool slowPath = !fastValidate || (instrEnd < fastStartAddr) || (instrEnd > fastEndAddr);
			if (slowPath &&
				((!IsOffsetCodeSemanticsFast(data, readOnlySections, dataExternSections, instrEnd) && IsOffsetCodeSemanticsFast(data, readOnlySections, dataExternSections,location.address)) ||
				(!data->IsOffsetBackedByFile(instrEnd) && data->IsOffsetBackedByFile(location.address))))
			{
				string text = fmt::format("Instruction at {:#x} straddles a non-code section", location.address);
				function->CreateAutoAddressTag(location.arch, location.address, "Invalid Instruction", text, true);
				if (location.arch->GetInstructionAlignment() == 0)
					location.address++;
				else
					location.address += location.arch->GetInstructionAlignment();
				block->SetHasInvalidInstructions(true);
				break;
			}

			bool endsBlock = false;
			ArchAndAddr target;
			map<ArchAndAddr, set<ArchAndAddr>>::const_iterator indirectBranchIter, endIter;
			if (!delaySlotCount)
			{
				// Register the address as belonging to this block if not in a delay slot,
				// this prevents basic blocks from being split between an instruction and
				// any of its delay slots
				instrBlocks[location] = block;

				// Keep track of where the current 'group' of instructions started. A 'group'
				// is an instruction and all of its delay slot instructions.
				instructionGroupStart = location;

				// Don't process branches in delay slots
				for (size_t i = 0; i < info.branchCount; i++)
				{
					bool fastPath;

					auto handleAsFallback = [&]() {
						// Undefined type or target, check for targets from analysis and stop disassembling this block
						endsBlock = true;

						if (info.branchType[i] == IndirectBranch)
						{
							// Indirect calls need not end the block early.
							Ref<LowLevelILFunction> ilFunc = new LowLevelILFunction(location.arch, nullptr);
							location.arch->GetInstructionLowLevelIL(opcode, location.address, maxLen, *ilFunc);
							for (size_t idx = 0; idx < ilFunc->GetInstructionCount(); idx++)
							{
								if ((*ilFunc)[idx].operation == LLIL_CALL)
								{
									endsBlock = false;
									break;
								}
							}
						}

						indirectBranchIter = indirectBranches.find(location);
						endIter = indirectBranches.end();
						if (indirectBranchIter != endIter)
						{
							for (auto& branch : indirectBranchIter->second)
							{
								directRefs[branch.address].emplace(location);
								Ref<Platform> targetPlatform = funcPlatform;
								if (branch.arch != function->GetArchitecture())
									targetPlatform = funcPlatform->GetRelatedPlatform(branch.arch);

								// Normal analysis should not inline indirect targets that are function starts
								if (translateTailCalls && data->GetAnalysisFunction(targetPlatform, branch.address))
									continue;

								if (isGuidedSourceBlock)
									guidedSourceBlockTargets.insert(branch);

								block->AddPendingOutgoingEdge(IndirectBranch, branch.address, branch.arch);
								if (seenBlocks.count(branch) == 0)
								{
									blocksToProcess.push(branch);
									seenBlocks.insert(branch);
								}
							}
						}
						else if (info.branchType[i] == ExceptionBranch)
						{
							block->SetCanExit(false);
						}
						else if (info.branchType[i] == FunctionReturn && function->CanReturn().GetValue())
						{
							// Support for contextual function returns. This is mainly used for ARM/Thumb with 'blx lr'. It's most common for this to be treated
							// as a function return, however it can also be a function call. For now this transform is described as follows:
							// 1) Architecture lifts a call instruction as LLIL_CALL with a branch type of FunctionReturn
							// 2) By default, contextualFunctionReturns is used to translate this to a LLIL_RET (conservative)
							// 3) Downstream analysis uses dataflow to validate the return target
							// 4) If the target is not the ReturnAddressValue, then we avoid the translation to a return and leave the instruction as a call
							if (auto it = contextualFunctionReturns.find(location); it != contextualFunctionReturns.end())
								endsBlock = it->second;
							else
							{
								Ref<LowLevelILFunction> ilFunc = new LowLevelILFunction(location.arch, nullptr);
								location.arch->GetInstructionLowLevelIL(opcode, location.address, maxLen, *ilFunc);
								if (ilFunc->GetInstructionCount() && ((*ilFunc)[0].operation == LLIL_CALL))
									contextualFunctionReturns[location] = true;
							}
						}
						else
						{
							// If analysis did not find any valid branch targets, don't assume anything about global
							// function state, such as __noreturn analysis, since we can't see the entire function->
							block->SetUndeterminedOutgoingEdges(true);
						}
					};

					switch (info.branchType[i])
					{
					case UnconditionalBranch:
					case TrueBranch:
					case FalseBranch:
						// Normal branch, resume disassembly at targets
						endsBlock = true;
						// Target of a call instruction, add the function to the analysis
						if (IsOffsetExternSemanticsFast(data, externSections, info.branchTarget[i]))
						{
							// Deal with direct pointers into the extern section
							DataVariable dataVar;
							if (data->GetDataVariableAtAddress(info.branchTarget[i], dataVar)
								&& (dataVar.address == info.branchTarget[i]) && dataVar.type.GetValue()
								&& (dataVar.type->GetClass() == FunctionTypeClass))
							{
								directRefs[info.branchTarget[i]].emplace(location);
								if (!dataVar.type->CanReturn())
								{
									directNoReturnCalls.insert(location);
									endsBlock = true;
									block->SetCanExit(false);
								}
							}
							break;
						}

						fastPath = fastValidate && (info.branchTarget[i] >= fastStartAddr) && (info.branchTarget[i] <= fastEndAddr);
						if (fastPath || (data->IsValidOffset(info.branchTarget[i]) &&
							data->IsOffsetBackedByFile(info.branchTarget[i]) &&
							((!validateExecutable) || data->IsOffsetExecutable(info.branchTarget[i]))))
						{
							target = ArchAndAddr(info.branchArch[i] ? new CoreArchitecture(info.branchArch[i]) : location.arch, info.branchTarget[i]);

							// Check if valid target
							if (data->ShouldSkipTargetAnalysis(location, function, instrEnd, target))
								break;

							Ref<Platform> targetPlatform = funcPlatform;
							if (target.arch != funcPlatform->GetArchitecture())
								targetPlatform = funcPlatform->GetRelatedPlatform(target.arch);

							directRefs[info.branchTarget[i]].insert(location);

							auto otherFunc = function->GetCalleeForAnalysis(targetPlatform, target.address, true);
							if (translateTailCalls && targetPlatform && otherFunc && (otherFunc->GetStart() != function->GetStart()))
							{
								calledFunctions.insert(otherFunc);
								if (info.branchType[i] == UnconditionalBranch)
								{
									if (!otherFunc->CanReturn() && !otherFunc->IsInlinedDuringAnalysis().GetValue())
									{
										directNoReturnCalls.insert(location);
										endsBlock = true;
										block->SetCanExit(false);
									}

									break;
								}
							}
							else if (disallowBranchToString && data->GetStringAtAddress(target.address, strRef) && targetExceedsByteLimit(strRef))
							{
								BNLogInfo("Not adding branch target from 0x%" PRIx64 " to string at 0x%" PRIx64
									" length:%zu",
									location.address, target.address, strRef.length);
								break;
							}
							else
							{
								if (isGuidedSourceBlock)
									guidedSourceBlockTargets.insert(target);

								block->AddPendingOutgoingEdge(info.branchType[i], target.address, target.arch);
								// Add the block to the list of blocks to process if it is not already processed
								if (seenBlocks.count(target) == 0)
								{
									blocksToProcess.push(target);
									seenBlocks.insert(target);
								}
							}
						}
						break;

					case CallDestination:
						// Target of a call instruction, add the function to the analysis
						if (IsOffsetExternSemanticsFast(data, externSections, info.branchTarget[i]))
						{
							// Deal with direct pointers into the extern section
							DataVariable dataVar;
							if (data->GetDataVariableAtAddress(info.branchTarget[i], dataVar)
								&& (dataVar.address == info.branchTarget[i]) && dataVar.type.GetValue()
								&& (dataVar.type->GetClass() == FunctionTypeClass))
							{
								directRefs[info.branchTarget[i]].emplace(location);
								if (!dataVar.type->CanReturn())
								{
									directNoReturnCalls.insert(location);
									endsBlock = true;
									block->SetCanExit(false);
								}
								// No need to add the target to the calledFunctions list since a call to external code
								// can never be the 'next' function
							}
							break;
						}

						fastPath = fastValidate && (info.branchTarget[i] >= fastStartAddr) && (info.branchTarget[i] <= fastEndAddr);
						if (fastPath || (data->IsValidOffset(info.branchTarget[i]) && data->IsOffsetBackedByFile(info.branchTarget[i]) &&
							((!validateExecutable) || data->IsOffsetExecutable(info.branchTarget[i]))))
						{
							target = ArchAndAddr(info.branchArch[i] ? new CoreArchitecture(info.branchArch[i]) : location.arch, info.branchTarget[i]);

							if (!fastPath && !IsOffsetCodeSemanticsFast(data, readOnlySections, dataExternSections, target.address) &&
								IsOffsetCodeSemanticsFast(data, readOnlySections, dataExternSections, location.address))
							{
								string message = fmt::format("Non-code call target {:#x}", target.address);
								function->CreateAutoAddressTag(target.arch, location.address, "Non-code Branch", message, true);
								break;
							}

							Ref<Platform> platform = funcPlatform;
							if (target.arch != platform->GetArchitecture())
							{
								platform = funcPlatform->GetRelatedPlatform(target.arch);
								if (!platform)
									platform = funcPlatform;
							}

							// Check if valid target
							if (data->ShouldSkipTargetAnalysis(location, function, instrEnd, target))
								break;

							Ref<Function> func = data->AddFunctionForAnalysis(platform, target.address, true);
							if (!func)
							{
								if (!data->IsOffsetBackedByFile(target.address))
									BNLogError("Function at 0x%" PRIx64 " failed to add target not backed by file.", function->GetStart());
								break;
							}


							// Add function as an early reference in case it gets updated before this
							// function finishes analysis.
							context.AddTempOutgoingReference(func);

							calledFunctions.emplace(func);

							directRefs[target.address].emplace(location);
							if (!func->CanReturn())
							{
								if (func->IsInlinedDuringAnalysis().GetValue() && func->HasUnresolvedIndirectBranches())
								{
									auto unresolved = func->GetUnresolvedIndirectBranches();
									if (unresolved.size() == 1)
									{
										inlinedUnresolvedIndirectBranches[location] = *unresolved.begin();
										handleAsFallback();
										break;
									}
								}

								directNoReturnCalls.insert(location);
								endsBlock = true;
								block->SetCanExit(false);
							}
						}
						break;

					case SystemCall:
						break;

					default:
						handleAsFallback();
						break;
					}
				}
			}

			if (indirectNoReturnCalls.count(location))
			{
				size_t instrLength = info.length;
				if (info.delaySlots)
				{
					InstructionInfo delayInfo;
					delayInfo.delaySlots = info.delaySlots; // we'll decrement this inside the loop
					size_t archMax = location.arch->GetMaxInstructionLength();
					uint8_t delayOpcode[BN_MAX_INSTRUCTION_LENGTH];
					do
					{
						delayInfo.delaySlots--;
						if (!location.arch->GetInstructionInfo(delayOpcode, location.address + instrLength, archMax - instrLength, delayInfo))
							break;
						instrLength += delayInfo.length;
					} while (delayInfo.delaySlots && (instrLength < archMax));
				}

				// Conditional Call Support (Part 1)
				// Do not halt basic block analysis if this is a conditional call to a function that is 'no return'
				// This works for both direct and indirect calls.
				// Note: Do not lift a conditional call (direct or not) with branch information.
				Ref<LowLevelILFunction> ilFunc = new LowLevelILFunction(location.arch, nullptr);
				ilFunc->SetCurrentAddress(location.arch, location.address);
				location.arch->GetInstructionLowLevelIL(opcode, location.address, maxLen, *ilFunc);
				if (!(ilFunc->GetInstructionCount() && ((*ilFunc)[0].operation == LLIL_IF)))
				{
					endsBlock = true;
					block->SetCanExit(false);
				}
			}

			location.address += info.length;
			block->AddInstructionData(opcode, info.length);

			if (endsBlock && !info.delaySlots)
				break;

			// Respect the 'analysis.limits.maxFunctionSize' setting while allowing for overridable behavior as well.
			// We prefer to allow disassembly when function analysis is disabled, but only up to the maximum size.
			// The log message and tag are generated in ProcessAnalysisSkip
			totalSize += info.length;
			auto analysisSkipOverride = context.GetAnalysisSkipOverride();
			if (analysisSkipOverride == NeverSkipFunctionAnalysis)
				maxSize = 0;
			else if (!maxSize && (analysisSkipOverride == AlwaysSkipFunctionAnalysis))
				maxSize = context.GetMaxFunctionSize();

			if (maxSize && (totalSize > maxSize))
			{
				maxSizeReached = true;
				break;
			}

			if (delaySlotCount)
			{
				delaySlotCount--;
				if (!delaySlotCount && delayInstructionEndsBlock)
					break;
			}
			else
			{
				delaySlotCount = info.delaySlots;
				delayInstructionEndsBlock = endsBlock;
			}

			if (block->CanExit() && translateTailCalls && !delaySlotCount && hasNextFunc && (location.address == nextFuncAddr))
			{
				// Falling through into another function->  Don't consider this a tail call if the current block
				// called the function, as this indicates a get PC construct.
				if (calledFunctions.count(nextFunc) == 0)
				{
					block->SetFallThroughToFunction(true);
					if (!nextFunc->CanReturn())
					{
						directNoReturnCalls.insert(instructionGroupStart);
						block->SetCanExit(false);
					}
					break;
				}
				hasNextFunc = GetNextFunctionAfterAddress(data, funcPlatform, location.address, nextFunc);
				nextFuncAddr = (hasNextFunc && nextFunc) ? nextFunc->GetStart() : 0;
			}
		}

		if (location.address != block->GetStart())
		{
			// Block has one or more instructions, add it to the fucntion
			block->SetEnd(location.address);
			context.AddFunctionBasicBlock(block);
		}

		if (maxSizeReached)
			break;

		if (triggerGuidedOnInvalidInstruction && block->HasInvalidInstructions())
			hasInvalidInstructions = true;

		if (guidedAnalysisMode || hasInvalidInstructions || guidedSourceBlocksSet.size())
		{
			queue<ArchAndAddr> guidedBlocksToProcess;
			while (!blocksToProcess.empty())
			{
				auto i = blocksToProcess.front();
				blocksToProcess.pop();
				if (guidedSourceBlockTargets.count(i))
					guidedBlocksToProcess.emplace(i);
				else
					haltedDisassemblyAddresses.emplace(i);
			}
			blocksToProcess = guidedBlocksToProcess;
		}
	}

	if (maxSizeReached)
		context.SetMaxSizeReached(true);

	// Finalize the function basic block list
	context.Finalize();
}


void Architecture::DefaultAnalyzeBasicBlocksCallback(BNFunction* function, BNBasicBlockAnalysisContext* context)
{
	Ref<Function> func(new Function(BNNewFunctionReference(function)));
	BasicBlockAnalysisContext abbc(context);
	Architecture::DefaultAnalyzeBasicBlocks(func, abbc);
}
