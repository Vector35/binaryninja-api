#include <map>
#include <set>
#include <queue>
#include <inttypes.h>
#include "binaryninjaapi.h"
#include "binaryninjacore.h"
#include "lowlevelilinstruction.h"

using namespace std;
using namespace BinaryNinja;

static bool GetNextFunctionAfterAddress(Ref<BinaryView> data, Ref<Platform> platform, uint64_t address, Ref<Function>& nextFunc)
{
	uint64_t nextFuncAddr = data->GetNextFunctionStartAfterAddress(address);
	nextFunc = data->GetAnalysisFunction(platform, nextFuncAddr);
	return nextFunc != nullptr;
}

static bool IsZeroConstant(LowLevelILInstruction expr)
{
	return ((expr.operation == LLIL_CONST) || (expr.operation == LLIL_CONST_PTR)) && (expr.GetConstant() == 0);
}


static bool ConstantCompare(LowLevelILInstruction expr, uint64_t value)
{
	return ((expr.operation == LLIL_CONST) || (expr.operation == LLIL_CONST_PTR)) && ((uint64_t)expr.GetConstant() == value);
}


static bool IsReturnAddressRegisterExpr(LowLevelILInstruction expr, const set<uint32_t>& returnAddressRegisters)
{
	switch (expr.operation)
	{
	case LLIL_REG:
		return returnAddressRegisters.count(expr.GetSourceRegister<LLIL_REG>()) != 0;
	case LLIL_ADD:
		return (IsReturnAddressRegisterExpr(expr.GetLeftExpr<LLIL_ADD>(), returnAddressRegisters)
				&& IsZeroConstant(expr.GetRightExpr<LLIL_ADD>()))
			|| (IsZeroConstant(expr.GetLeftExpr<LLIL_ADD>())
				&& IsReturnAddressRegisterExpr(expr.GetRightExpr<LLIL_ADD>(), returnAddressRegisters));
	case LLIL_SUB:
		return IsReturnAddressRegisterExpr(expr.GetLeftExpr<LLIL_SUB>(), returnAddressRegisters)
			&& IsZeroConstant(expr.GetRightExpr<LLIL_SUB>());
	default:
		return false;
	}
}


static void RemoveWrittenReturnAddressRegisters(LowLevelILInstruction instr, set<uint32_t>& returnAddressRegisters)
{
	switch (instr.operation)
	{
	case LLIL_SET_REG:
		returnAddressRegisters.erase(instr.GetDestRegister<LLIL_SET_REG>());
		break;
	case LLIL_SET_REG_SPLIT:
		returnAddressRegisters.erase(instr.GetHighRegister<LLIL_SET_REG_SPLIT>());
		returnAddressRegisters.erase(instr.GetLowRegister<LLIL_SET_REG_SPLIT>());
		break;
	default:
		break;
	}
}


static bool IsReturnAddressRegisterJumpOrReturn(LowLevelILInstruction instr, const set<uint32_t>& returnAddressRegisters)
{
	switch (instr.operation)
	{
	case LLIL_JUMP:
		return IsReturnAddressRegisterExpr(instr.GetDestExpr<LLIL_JUMP>(), returnAddressRegisters);
	case LLIL_RET:
		return IsReturnAddressRegisterExpr(instr.GetDestExpr<LLIL_RET>(), returnAddressRegisters);
	default:
		return false;
	}
}


// Returning overrides need a continuation even when another branch ends the block.
static void AddBranchOverrideContinuations(const set<BNBranchType>& overrideContinuations, BasicBlock* block,
	const ArchAndAddr& location, set<ArchAndAddr>& seenBlocks, queue<ArchAndAddr>& blocksToProcess)
{
	block->SetCanExit(true);
	for (auto type : overrideContinuations)
	{
		if ((type != TrueBranch) && (type != FalseBranch))
			type = UnconditionalBranch;
		const auto& edges = block->GetPendingOutgoingEdges();
		if (none_of(edges.begin(), edges.end(), [&](const auto& edge) {
			return (edge.type == type) && (edge.target == location.address);
		}))
			block->AddPendingOutgoingEdge(type, location.address, location.arch, true);
	}
	if (seenBlocks.insert(location).second)
		blocksToProcess.push(location);
}


// NOPs have no ordinary branch metadata. Add it only at a user override site.
// A NOP replacement suppresses the whole native instruction, including all branch arms.
static bool ApplyNopInstructionInfoOverride(Function* function, BasicBlockAnalysisContext& context,
	const ArchAndAddr& location, InstructionInfo& info)
{
	const auto& overrides = context.GetBranchOverrides();
	auto entry = overrides.find(location);
	if (entry == overrides.end())
		return false;
	if (!info.branchCount && entry->second.count(NopBranch))
	{
		for (const auto& branch : location.arch->GetBranchTypesWithContext(function, location.address,
			context.GetFunctionArchContextRaw()))
			if (branch.type == NopBranch)
				info.AddBranch(NopBranch);
	}
	for (size_t i = 0; i < info.branchCount; i++)
	{
		auto replacement = entry->second.find(info.branchType[i]);
		if ((replacement != entry->second.end()) && (replacement->second.type == NopBranch))
		{
			info.branchCount = 0;
			info.delaySlots = 0;
			info.AddBranch(NopBranch);
			return true;
		}
	}
	return false;
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
	auto& branchOverrides = context.GetBranchOverrides();

	auto& contextualFunctionReturns = context.GetContextualReturns();

	auto& directRefs = context.GetDirectCodeReferences();
	auto& directNoReturnCalls = context.GetDirectNoReturnCalls();
	auto& haltedDisassemblyAddresses = context.GetHaltedDisassemblyAddresses();
	auto& inlinedUnresolvedIndirectBranches = context.GetInlinedUnresolvedIndirectBranches();

	Ref<LifterInstructionData> instrData = context.GetLifterInstructionData();

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
		set<BNBranchType> overrideContinuations;

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
						if (instrData)
						{
							// Copy before appending, as Append can invalidate the span returned by Get
							std::span<const uint8_t> tail = instrData->Get(targetBlock, location.address);
							std::vector<uint8_t> splitData(tail.begin(), tail.end());
							instrData->Append(splitBlock, splitData);
						}
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
				((!data->IsOffsetCodeSemantics(instrEnd) && data->IsOffsetCodeSemantics(location.address)) ||
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

			bool suppressInstruction = !delaySlotCount && !branchOverrides.empty()
				&& ApplyNopInstructionInfoOverride(function, context, location, info);
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
				overrideContinuations.clear();

				// Don't process branches in delay slots
				for (size_t i = 0; i < info.branchCount; i++)
				{
					bool fastPath;
					auto branchType = info.branchType[i];
					auto branchTarget = info.branchTarget[i];
					Ref<Architecture> branchTargetArch =
						info.branchArch[i] ? new CoreArchitecture(info.branchArch[i]) : nullptr;
					bool branchOverridden = false;
					if (auto locationOverrides = branchOverrides.find(location);
						locationOverrides != branchOverrides.end())
					{
						if (auto branchOverride = locationOverrides->second.find(branchType);
							branchOverride != locationOverrides->second.end())
						{
							branchType = branchOverride->second.type;
							branchOverridden = true;
							if (branchOverride->second.target)
							{
								branchTarget = *branchOverride->second.target;
								branchTargetArch = branchOverride->second.targetArch;
							}
						}
					}

					auto handleAsFallback = [&]() {
						// Undefined type or target, check for targets from analysis and stop disassembling this block
						endsBlock = true;

						if (branchType == IndirectBranch)
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
						if (indirectBranchIter != endIter && (!branchOverridden
							|| ((branchType != ExceptionBranch) && (branchType != FunctionReturn))))
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
						else if (branchType == ExceptionBranch)
						{
							block->SetCanExit(false);
						}
						else if (branchOverridden && (branchType == FunctionReturn))
						{
							// An explicit return override takes precedence over contextual return detection.
							return;
						}
						else if (branchType == FunctionReturn && function->CanReturn().GetValue())
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
								// A linked return may save its target and update the link register before the call.
								// Match the final call, which is the instruction translated to LLIL_RET during lifting.
								if (ilFunc->GetInstructionCount()
									&& ((*ilFunc)[ilFunc->GetInstructionCount() - 1].operation == LLIL_CALL))
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

					if (info.branchType[i] != SystemCall)
						context.GetValidBranchOverrideLocations().insert(location);

					bool returningOverride = branchOverridden
						&& ((branchType == CallDestination) || (branchType == SystemCall));
					switch (branchType)
					{
					case UnconditionalBranch:
					case TrueBranch:
					case FalseBranch:
						// Normal branch, resume disassembly at targets
						endsBlock = true;
						// Target of a call instruction, add the function to the analysis
						if (data->IsOffsetExternSemantics(branchTarget))
						{
							// Deal with direct pointers into the extern section
							DataVariable dataVar;
							if (data->GetDataVariableAtAddress(branchTarget, dataVar)
								&& (dataVar.address == branchTarget) && dataVar.type.GetValue()
								&& (dataVar.type->GetClass() == FunctionTypeClass))
							{
								directRefs[branchTarget].emplace(location);
								if (!dataVar.type->CanReturn())
								{
									directNoReturnCalls.insert(location);
									endsBlock = true;
									block->SetCanExit(false);
								}
							}
							break;
						}

						fastPath = fastValidate && (branchTarget >= fastStartAddr) && (branchTarget <= fastEndAddr);
						if (fastPath || (data->IsValidOffset(branchTarget) &&
							data->IsOffsetBackedByFile(branchTarget) &&
							((!validateExecutable) || data->IsOffsetExecutable(branchTarget))))
						{
							target = ArchAndAddr(branchTargetArch ? branchTargetArch : location.arch, branchTarget);

							// Check if valid target
							if (data->ShouldSkipTargetAnalysis(location, function, instrEnd, target))
								break;

							Ref<Platform> targetPlatform = funcPlatform;
							if (target.arch != funcPlatform->GetArchitecture())
								targetPlatform = funcPlatform->GetRelatedPlatform(target.arch);

							directRefs[branchTarget].insert(location);

							auto otherFunc = function->GetCalleeForAnalysis(targetPlatform, target.address, true);
							if (!branchOverridden && translateTailCalls && targetPlatform && otherFunc
								&& (otherFunc->GetStart() != function->GetStart()))
							{
								calledFunctions.insert(otherFunc);
								if (branchType == UnconditionalBranch)
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

								block->AddPendingOutgoingEdge(branchType, target.address, target.arch);
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
						if (data->IsOffsetExternSemantics(branchTarget))
						{
							// Deal with direct pointers into the extern section
							DataVariable dataVar;
							if (data->GetDataVariableAtAddress(branchTarget, dataVar)
								&& (dataVar.address == branchTarget) && dataVar.type.GetValue()
								&& (dataVar.type->GetClass() == FunctionTypeClass))
							{
								directRefs[branchTarget].emplace(location);
								if (!dataVar.type->CanReturn())
								{
									returningOverride = false;
									directNoReturnCalls.insert(location);
									endsBlock = true;
									block->SetCanExit(false);
								}
								// No need to add the target to the calledFunctions list since a call to external code
								// can never be the 'next' function
							}
							break;
						}

						fastPath = fastValidate && (branchTarget >= fastStartAddr) && (branchTarget <= fastEndAddr);
						if (fastPath || (data->IsValidOffset(branchTarget) && data->IsOffsetBackedByFile(branchTarget) &&
							((!validateExecutable) || data->IsOffsetExecutable(branchTarget))))
						{
							target = ArchAndAddr(branchTargetArch ? branchTargetArch : location.arch, branchTarget);

							if (!fastPath && !data->IsOffsetCodeSemantics(target.address) && data->IsOffsetCodeSemantics(location.address))
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
								returningOverride = false;
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
					case NopBranch:
						break;

					default:
						handleAsFallback();
						break;
					}
					if (returningOverride)
						overrideContinuations.insert(info.branchType[i]);
				}
			}

			if (!suppressInstruction && indirectNoReturnCalls.count(location))
			{
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
			if (instrData)
				instrData->Append(block, std::span<const uint8_t>(opcode, info.length));

			if (endsBlock && !info.delaySlots)
			{
				if (!overrideContinuations.empty())
					AddBranchOverrideContinuations(overrideContinuations, block, location, seenBlocks, blocksToProcess);
				break;
			}

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
				{
					if (!overrideContinuations.empty())
						AddBranchOverrideContinuations(overrideContinuations, block, location, seenBlocks, blocksToProcess);
					break;
				}
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


static void ApplyExternPointerForRelocation(
	int64_t operand, LowLevelILFunction& il, size_t start, size_t end, Ref<Relocation> relocation, Ref<Logger> logger)
{
	ExprId id = (ExprId)-1;
	uint64_t offset = 0;
	size_t size = 0;

	uint64_t relocStart = relocation->GetAddress();
	uint64_t relocEnd = relocStart + relocation->GetInfo().size;

	if (operand == BN_AUTOCOERCE_EXTERN_PTR)
	{
		// Go through all expressions looking for just one LLIL_CONST expression
		size_t count = 0;
		for (size_t i = start; i < end; i++)
		{
			auto instr = il.GetInstruction(i);

			// because multiple instructions can be lifted at once, we want to ensure that
			// each relocation is only checked against IL instructions that potentially
			// overlap. this is hard/impossible to do robustly (reloc will not always be
			// at the start of an instruction), but we can at least rule out instructions
			// that start after the candidate reloc ends (as in MIPS delay slots, which this
			// fixes)
			if (instr.address >= relocEnd)
				continue;

			instr.VisitExprs([&](const LowLevelILInstruction& expr) {
				switch (expr.operation)
				{
				case LLIL_CONST:
				case LLIL_CONST_PTR:
					id = expr.exprIndex;
					offset = expr.operands[0];
					size = expr.size;
					count++;
					break;
				default:
					break;
				}
				return true;
			});
			// If there is more than one LLIL_CONST then we don't know which one to set
			// as an external pointer.
			if (count > 1)
				return;
		}
		if (count != 1)
			return;
	}
	else
	{
		for (size_t i = start; i < end; i++)
		{
			auto instr = il.GetInstruction(i);
			instr.VisitExprs([&](const LowLevelILInstruction& expr) {
				if (expr.sourceOperand == operand)
				{
					switch (expr.operation)
					{
					case LLIL_CONST:
					case LLIL_CONST_PTR:
						id = expr.exprIndex;
						offset = expr.operands[0];
						size = expr.size;
						return false;
					default:
						break;
					}
				}
				return true;  // Parse any subexpressions
			});
			if (id != (ExprId)-1)
				break;
		}
	}

	if (id == (ExprId)-1)
	{
		logger->LogWarn("Unable to find const or const_ptr in expresssion @ %08" PRIx64 ":%zu", il.GetCurrentAddress(), start);
		return;
	}
	offset = offset - relocation->GetTarget();
	il.ReplaceExpr(id, il.ExternPointer(size, relocation->GetTarget(), offset));
}


// An isolated lift has only local labels: native destinations remain address expressions.
// Plan every replacement before copying anything into the real function, then re-emit local
// branches with fresh labels. Replacing expressions in place would invalidate label fixups.
static bool ApplyLiftedBranchOverrides(LowLevelILFunction& dest, LowLevelILFunction& source,
	FunctionLifterContext& context, const ArchAndAddr& location, uint64_t continuationAddress,
	const vector<OverridableBranchInfo>& branches, const map<BNBranchType, BranchOverride>& overrides)
{
	struct Exit
	{
		size_t index;
		BNLowLevelILOperation operation;
		optional<LowLevelILInstruction> target;
	};
	const size_t count = source.GetInstructionCount();
	const bool originalNop = (branches.size() == 1) && (branches.front().type == NopBranch);
	vector<Exit> exits;
	set<size_t> visited, labelTargets;
	queue<size_t> pending;
	pending.push(0);
	while (!pending.empty())
	{
		size_t index = pending.front();
		pending.pop();
		if (index > count)
			return false;
		if (!visited.insert(index).second)
			continue;
		if (index == count)
		{
			exits.push_back({index, LLIL_NOP,
				source.GetExpr(source.ConstPointer(location.arch->GetAddressSize(), continuationAddress))});
			continue;
		}
		auto instr = source.GetInstruction(index);
		auto follow = [&](size_t target) {
			labelTargets.insert(target);
			pending.push(target);
		};
		switch (instr.operation)
		{
		case LLIL_IF:
			follow(instr.GetTrueTarget<LLIL_IF>());
			follow(instr.GetFalseTarget<LLIL_IF>());
			break;
		case LLIL_GOTO:
			follow(instr.GetTarget<LLIL_GOTO>());
			break;
		case LLIL_CALL:
		case LLIL_CALL_STACK_ADJUST:
			exits.push_back({index, instr.operation, instr.GetDestExpr()});
			pending.push(index + 1);
			break;
		case LLIL_JUMP:
		case LLIL_RET:
		case LLIL_TAILCALL:
			exits.push_back({index, instr.operation, instr.GetDestExpr()});
			break;
		case LLIL_JUMP_TO:
			exits.push_back({index, instr.operation, instr.GetDestExpr()});
			for (const auto& target : instr.GetTargets<LLIL_JUMP_TO>())
				follow(target.second);
			break;
		case LLIL_SYSCALL:
			exits.push_back({index, instr.operation, nullopt});
			pending.push(index + 1);
			break;
		case LLIL_TRAP:
		case LLIL_NORET:
		case LLIL_UNDEF:
			exits.push_back({index, instr.operation, nullopt});
			break;
		default:
			pending.push(index + 1);
			break;
		}
	}

	map<size_t, pair<const BranchOverride*, Ref<Architecture>>> replacements;
	for (const auto& branch : branches)
	{
		auto replacement = overrides.find(branch.type);
		if (replacement == overrides.end())
			continue;
		vector<const Exit*> matches;
		for (const auto& exit : exits)
		{
			bool match = false;
			switch (branch.type)
			{
			case UnconditionalBranch:
			case TrueBranch:
			case FalseBranch:
				match = exit.target && ConstantCompare(*exit.target, branch.target);
				break;
			case CallDestination:
				match = ((exit.operation == LLIL_CALL) || (exit.operation == LLIL_CALL_STACK_ADJUST))
					&& exit.target && ConstantCompare(*exit.target, branch.target);
				break;
			case FunctionReturn:
				match = exit.operation == LLIL_RET;
				break;
			case NopBranch:
				match = exit.index == count;
				break;
			case IndirectBranch:
			case UnresolvedBranch:
				// Architectures may recognize an indirect jump as a tail call during the initial lift.
				match = (exit.operation == LLIL_JUMP) || (exit.operation == LLIL_JUMP_TO)
					|| (exit.operation == LLIL_TAILCALL);
				break;
			case ExceptionBranch:
				match = (exit.operation == LLIL_TRAP) || (exit.operation == LLIL_NORET);
				break;
			default:
				break;
			}
			if (match)
				matches.push_back(&exit);
		}
		// Contextual returns may lift as calls or jumps; indirect calls have no constant target.
		if (matches.empty() && ((branch.type == FunctionReturn) || (branch.type == CallDestination)))
		{
			for (const auto& exit : exits)
			{
				if ((exit.operation == LLIL_CALL) || (exit.operation == LLIL_CALL_STACK_ADJUST)
					|| ((branch.type == FunctionReturn)
						&& ((exit.operation == LLIL_JUMP) || (exit.operation == LLIL_TAILCALL))))
					matches.push_back(&exit);
			}
		}
		if ((matches.size() != 1) || replacements.count(matches.front()->index))
			return false;
		auto& value = replacement->second;
		switch (value.type)
		{
		case UnconditionalBranch:
		case TrueBranch:
		case FalseBranch:
		case CallDestination:
		case FunctionReturn:
		case IndirectBranch:
		case UnresolvedBranch:
			if (!value.target && !matches.front()->target)
				return false;
			break;
		case ExceptionBranch:
		case SystemCall:
			break;
		default:
			return false;
		}
		replacements.emplace(matches.front()->index, make_pair(&value, branch.arch));
	}

	vector<LowLevelILLabel> labels(count + 1);
	LowLevelILLabel continuation;
	bool needsContinuation = false;
	vector<ArchAndAddr> indirectTargets;
	if (dest.HasIndirectBranches())
	{
		const auto& userTargets = context.GetUserIndirectBranches();
		const auto& autoTargets = context.GetAutoIndirectBranches();
		if (auto it = userTargets.find(location); it != userTargets.end())
			indirectTargets.assign(it->second.begin(), it->second.end());
		else if (auto it = autoTargets.find(location); it != autoTargets.end())
			indirectTargets.assign(it->second.begin(), it->second.end());
	}
	function<ExprId(const LowLevelILInstruction&)> copyExpr = [&](const LowLevelILInstruction& expr) {
		auto result = expr.CopyTo(&dest, copyExpr);
		dest.SetExprAttributes(result, expr.attributes);
		return result;
	};
	auto emitJump = [&](ExprId target, Architecture* arch, const ILSourceLocation& loc) {
		auto expr = dest.GetExpr(target);
		if ((expr.operation == LLIL_CONST) || (expr.operation == LLIL_CONST_PTR))
		{
			if (auto label = dest.GetLabelForAddress(arch, expr.GetConstant()))
				return dest.Goto(*label, loc);
		}
		return dest.Jump(target, loc);
	};
	optional<uint32_t> temporary;
	auto allocateTemporary = [&]() {
		// Counting temporaries scans the IL. Constant branch replacements need none.
		if (!temporary)
			temporary = max(dest.GetTemporaryRegisterCount(), source.GetTemporaryRegisterCount());
		return LLIL_TEMP((*temporary)++);
	};
	for (size_t index = 0; index <= count; index++)
	{
		if (!visited.count(index))
			continue;
		if (labelTargets.count(index))
			dest.MarkLabel(labels[index]);
		auto replacement = replacements.find(index);
		if (replacement != replacements.end())
		{
			const auto& value = *replacement->second.first;
			auto exit = find_if(exits.begin(), exits.end(), [&](const Exit& exit) { return exit.index == index; });
			ILSourceLocation loc = index < count ? ILSourceLocation(source.GetInstruction(index))
				: ILSourceLocation(location.address, BN_INVALID_OPERAND);
			dest.SetCurrentAddress(location.arch, loc.address);
			bool needsTarget = (value.type != ExceptionBranch) && (value.type != SystemCall);
			// A discarded target can contain effects, e.g. x86 RET(POP()). Evaluate it once
			// before replacing the transfer; ordinary dead-store elimination removes pure values.
			if (exit->target && (value.target || !needsTarget))
			{
				auto oldTarget = *exit->target;
				if ((oldTarget.operation != LLIL_CONST) && (oldTarget.operation != LLIL_CONST_PTR))
					dest.AddInstruction(dest.SetRegister(oldTarget.size, allocateTemporary(), copyExpr(oldTarget), 0, loc));
			}
			Ref<Architecture> targetArch = value.target
				? (value.targetArch ? value.targetArch : location.arch)
				: (replacement->second.second ? replacement->second.second : location.arch);
			ExprId target = BN_INVALID_EXPR;
			if (needsTarget)
				target = value.target ? dest.ConstPointer(targetArch->GetAddressSize(), *value.target, loc)
					: copyExpr(*exit->target);
			if (originalNop && (value.type == FunctionReturn) && !value.target)
			{
				// A NOP has no return destination to preserve. Use the architecture's normal
				// return address, just as a newly introduced call uses its normal return setup.
				uint32_t linkReg = location.arch->GetLinkRegister();
				target = linkReg == BN_INVALID_REGISTER ? dest.Pop(location.arch->GetAddressSize(), 0, loc)
					: dest.Register(location.arch->GetRegisterInfo(linkReg).size, linkReg, loc);
			}
			if (((exit->operation == LLIL_CALL) || (exit->operation == LLIL_CALL_STACK_ADJUST))
				&& (value.type != CallDestination))
			{
				// CALL includes implicit return-address setup. Materialize it when removing
				// the call, evaluating its destination before changing SP or the link register.
				if (needsTarget && !value.target && (exit->target->operation != LLIL_CONST)
					&& (exit->target->operation != LLIL_CONST_PTR))
				{
					uint32_t reg = allocateTemporary();
					dest.AddInstruction(dest.SetRegister(exit->target->size, reg, target, 0, loc));
					target = dest.Register(exit->target->size, reg, loc);
				}
				uint32_t linkReg = location.arch->GetLinkRegister();
				ExprId setup;
				if (linkReg == BN_INVALID_REGISTER)
				{
					size_t size = location.arch->GetAddressSize();
					setup = dest.Push(size, dest.ConstPointer(size, continuationAddress, loc), 0, loc);
				}
				else
				{
					size_t size = location.arch->GetRegisterInfo(linkReg).size;
					uint64_t returnAddress = continuationAddress;
					if ((location.arch->GetName() == "thumb2") || (location.arch->GetName() == "thumb2eb"))
						returnAddress |= 1;
					setup = dest.SetRegister(size, linkReg, dest.ConstPointer(size, returnAddress, loc), 0, loc);
				}
				dest.SetExprAttributes(setup, ILAllowDeadStoreElimination);
				dest.AddInstruction(setup);
			}
			ExprId transfer;
			switch (value.type)
			{
			case CallDestination:
				if (exit->operation == LLIL_CALL_STACK_ADJUST)
				{
					auto original = source.GetInstruction(index);
					transfer = dest.CallStackAdjust(target, original.GetStackAdjustment<LLIL_CALL_STACK_ADJUST>(),
						original.GetRegisterStackAdjustments<LLIL_CALL_STACK_ADJUST>(), loc);
				}
				else
					transfer = dest.Call(target, loc);
				break;
			case FunctionReturn:
				transfer = dest.Return(target, loc);
				break;
			case ExceptionBranch:
				transfer = dest.NoReturn(loc);
				break;
			case SystemCall:
				transfer = dest.SystemCall(loc);
				break;
			default:
				transfer = emitJump(target, targetArch, loc);
				break;
			}
			dest.SetExprAttributes(transfer, ILBranchOverride
				| (index < count ? source.GetInstruction(index).attributes : 0));
			bool hadIndirectTargets = dest.HasIndirectBranches();
			bool retainIndirectTargets = !value.target
				&& ((value.type == IndirectBranch) || (value.type == UnresolvedBranch));
			if (!retainIndirectTargets)
				dest.ClearIndirectBranches();
			dest.AddInstruction(transfer);
			if (hadIndirectTargets && !retainIndirectTargets)
				dest.SetIndirectBranches(indirectTargets);
			if (value.type == CallDestination)
			{
				bool noReturn = false;
				auto targetExpr = dest.GetExpr(target);
				if ((targetExpr.operation == LLIL_CONST) || (targetExpr.operation == LLIL_CONST_PTR))
				{
					for (auto& callee : context.GetView()->GetAnalysisFunctionsForAddress(targetExpr.GetConstant()))
						if ((callee->GetArchitecture() == targetArch) && !callee->CanReturn().GetValue())
							noReturn = true;
				}
				else if (!value.target && ((exit->operation == LLIL_CALL) || (exit->operation == LLIL_CALL_STACK_ADJUST)))
					noReturn = context.GetNoReturnCalls().count(location);
				if (noReturn)
					dest.AddInstruction(dest.NoReturn(loc));
				else if ((exit->operation != LLIL_CALL) && (exit->operation != LLIL_CALL_STACK_ADJUST)
					&& ((index + 1 < count) || replacements.count(count)))
				{
					dest.AddInstruction(dest.Goto(continuation, loc));
					needsContinuation = true;
				}
			}
			else if (value.type == SystemCall)
			{
				dest.AddInstruction(dest.Goto(continuation, loc));
				needsContinuation = true;
			}
			continue;
		}
		if (index == count)
			continue;
		auto instr = source.GetInstruction(index);
		dest.SetCurrentAddress(location.arch, instr.address);
		ExprId copied;
		switch (instr.operation)
		{
		case LLIL_IF:
			copied = dest.If(copyExpr(instr.GetConditionExpr<LLIL_IF>()), labels[instr.GetTrueTarget<LLIL_IF>()],
				labels[instr.GetFalseTarget<LLIL_IF>()], instr);
			break;
		case LLIL_GOTO:
			copied = dest.Goto(labels[instr.GetTarget<LLIL_GOTO>()], instr);
			break;
		case LLIL_JUMP:
		{
			Ref<Architecture> targetArch = location.arch;
			for (const auto& branch : branches)
				if (branch.arch && ConstantCompare(instr.GetDestExpr(), branch.target))
					targetArch = branch.arch;
			copied = emitJump(copyExpr(instr.GetDestExpr()), targetArch, instr);
			break;
		}
		case LLIL_JUMP_TO:
		{
			map<uint64_t, BNLowLevelILLabel*> targets;
			for (const auto& target : instr.GetTargets<LLIL_JUMP_TO>())
				targets[target.first] = &labels[target.second];
			copied = dest.JumpTo(copyExpr(instr.GetDestExpr<LLIL_JUMP_TO>()), targets, instr);
			break;
		}
		default:
			copied = copyExpr(instr);
			break;
		}
		dest.SetExprAttributes(copied, instr.attributes);
		dest.AddInstruction(copied);
	}
	if (needsContinuation)
		dest.MarkLabel(continuation);
	return true;
}


namespace
{
	// Created only for functions with user branch overrides. Ordinary instructions still
	// lift directly into the function; temporary IL exists only at matching override sites.
	class BranchOverrideLifter
	{
		LowLevelILFunction* m_function;
		FunctionLifterContext& m_context;
		const map<ArchAndAddr, map<BNBranchType, BranchOverride>>& m_overrides;
		const map<BNBranchType, BranchOverride>* m_currentOverrides = nullptr;
		vector<OverridableBranchInfo> m_originalBranches;
		Ref<LowLevelILFunction> m_staged;
		bool m_suppressInstruction = false;

		void limitCoalescing(const ArchAndAddr& location, size_t& len)
		{
			// A lifter must not consume a later override site while lifting an earlier instruction.
			for (auto next = m_overrides.upper_bound(location);
				next != m_overrides.end() && next->first.arch == location.arch
					&& (next->first.address - location.address < len); ++next)
			{
				if (m_function->GetFunction()->IsValidBranchOverrideLocation(location.arch, next->first.address))
				{
					len = next->first.address - location.address;
					break;
				}
			}
		}

		void limitToInstructionGroup(const ArchAndAddr& location, const uint8_t* opcode, size_t& len)
		{
			// Preserve delay slots, but exclude following instructions: a returning override
			// resumes immediately after this group.
			size_t groupLength = 0;
			unsigned remaining = 1;
			while (remaining && (groupLength < len))
			{
				InstructionInfo info;
				if (!location.arch->GetInstructionInfo(opcode + groupLength, location.address + groupLength,
					len - groupLength, info) || !info.length || (info.length > len - groupLength))
					break;
				remaining = groupLength ? remaining - 1 : (m_suppressInstruction ? 0 : info.delaySlots);
				groupLength += info.length;
			}
			if (!remaining)
				len = groupLength;
		}

	public:
		BranchOverrideLifter(LowLevelILFunction* function, FunctionLifterContext& context) :
			m_function(function), m_context(context), m_overrides(context.GetBranchOverrides())
		{}

		LowLevelILFunction* PrepareInstruction(BasicBlock* block, const ArchAndAddr& location,
			const uint8_t* opcode, size_t& len)
		{
			m_suppressInstruction = false;
			limitCoalescing(location, len);
			auto overrides = m_overrides.find(location);
			if (overrides == m_overrides.end())
				return m_function;

			m_originalBranches = location.arch->GetBranchTypesWithContext(m_function->GetFunction(), location.address,
				m_context.GetFunctionArchContextRaw());
			if (none_of(m_originalBranches.begin(), m_originalBranches.end(), [&](const auto& branch) {
				return overrides->second.count(branch.type);
			}))
				return m_function;

			m_currentOverrides = &overrides->second;
			m_suppressInstruction = any_of(m_originalBranches.begin(), m_originalBranches.end(), [&](const auto& branch) {
				auto replacement = overrides->second.find(branch.type);
				return (replacement != overrides->second.end()) && (replacement->second.type == NopBranch);
			});
			m_staged = new LowLevelILFunction(location.arch, m_function->GetFunction());
			m_staged->SetCurrentSourceBlock(block);
			m_staged->SetCurrentAddress(location.arch, location.address);
			limitToInstructionGroup(location, opcode, len);
			return m_staged.GetPtr();
		}

		bool IsNopOverride() const { return m_suppressInstruction; }

		bool LiftInstruction(BasicBlock* block, const ArchAndAddr& location, const uint8_t* opcode,
			size_t& len, LowLevelILFunction*& liftTarget)
		{
			liftTarget = PrepareInstruction(block, location, opcode, len);
			if (m_suppressInstruction)
			{
				liftTarget->AddInstruction(liftTarget->Nop());
				return true;
			}
			return location.arch->GetInstructionLowLevelIL(opcode, location.address, len, *liftTarget);
		}

		bool FinishInstruction(const ArchAndAddr& location, uint64_t continuationAddress,
			bool& status, size_t& instrCountAfter)
		{
			if (!m_staged)
				return true;

			bool applied = true;
			if (m_suppressInstruction)
			{
				auto nop = m_function->Nop(ILSourceLocation(location.address, BN_INVALID_OPERAND));
				m_function->SetExprAttributes(nop, ILBranchOverride);
				m_function->AddInstruction(nop);
			}
			else
				applied = ApplyLiftedBranchOverrides(*m_function, *m_staged, m_context, location,
					continuationAddress, m_originalBranches, *m_currentOverrides);
			m_staged = nullptr;
			if (!applied)
			{
				m_context.GetLogger()->LogWarn("Unable to match branch overrides to lifted control flow at %#" PRIx64
					" (%s); this instruction requires architecture-specific lifting support.",
					location.address, location.arch->GetName().c_str());
				return false;
			}

			// Lifters can return false for a valid terminator. An overridden call may now
			// continue, so use the analyzed block boundary after a successful rewrite.
			status = true;
			instrCountAfter = m_function->GetInstructionCount();
			return true;
		}
	};
}


bool Architecture::DefaultLiftFunction(LowLevelILFunction* function, FunctionLifterContext& context)
{
	unique_ptr<BranchOverrideLifter> overrideLifter;
	if (!context.GetBranchOverrides().empty())
		overrideLifter = make_unique<BranchOverrideLifter>(function, context);

	Ref<BinaryView> data = context.GetView();
	Ref<Logger> logger = context.GetLogger();
	Ref<Platform> platform = context.GetPlatform();
	std::set<ArchAndAddr> noReturnCalls = context.GetNoReturnCalls();
	std::vector<Ref<BasicBlock>> blocks = context.GetBasicBlocks();
	Ref<LifterInstructionData> lifterInstructionData = context.GetLifterInstructionData();
	FastBasicBlockMap<DataBuffer> instrData(blocks);
	std::map<ArchAndAddr, bool> contextualReturns = context.GetContextualReturns();
	std::map<ArchAndAddr, ArchAndAddr> inlinedRemapping = context.GetInlinedRemapping();
	std::optional<pair<ArchAndAddr, ArchAndAddr>> indirectSource;
	std::map<ArchAndAddr, std::set<ArchAndAddr>> userIndirectBranches = context.GetUserIndirectBranches();
	std::map<ArchAndAddr, std::set<ArchAndAddr>> autoIndirectBranches = context.GetAutoIndirectBranches();
	for (auto& i: blocks)
	{
		function->SetCurrentSourceBlock(i);

		auto relocationHandler = i->GetArchitecture()->GetRelocationHandler(data->GetTypeName());
		Ref<Relocation> nextRelocation;
		if (relocationHandler)
			nextRelocation = data->GetNextRelocation(i->GetStart());

		context.PrepareBlockTranslation(function, i->GetArchitecture(), i->GetStart());
		BNLowLevelILLabel* label = function->GetLabelForAddress(i->GetArchitecture(), i->GetStart());
		if (label)
			function->MarkLabel(*label);

		size_t beginInstrCount = function->GetInstructionCount();

		// Generate IL for each instruction in the block
		for (uint64_t addr = i->GetStart(); addr < i->GetEnd();) {
			if (data->AnalysisIsAborted())
				return false;

			ArchAndAddr cur(i->GetArchitecture(), addr);
			function->SetCurrentAddress(i->GetArchitecture(), addr);
			function->ClearIndirectBranches();

			if (auto it = inlinedRemapping.find(cur); it != inlinedRemapping.end())
			{
				indirectSource = *it;
			}
			else
			{
				if (auto brit = userIndirectBranches.find(cur); brit != userIndirectBranches.end())
				{
					const auto& s = brit->second;
					function->SetIndirectBranches(std::vector<ArchAndAddr>(s.begin(), s.end()));
				}
				else if (auto brit = autoIndirectBranches.find(cur); brit != autoIndirectBranches.end())
				{
					const auto& s = brit->second;
					function->SetIndirectBranches(std::vector<ArchAndAddr>(s.begin(), s.end()));
				}
			}

			size_t len = 0;
			const uint8_t* opcode = nullptr;
			if (lifterInstructionData)
			{
				std::span<const uint8_t> bytes = lifterInstructionData->Get(i, addr);
				opcode = bytes.data();
				len = bytes.size();
			}

			if (!opcode)
			{
				// The instruction data has no bytes for this block (a function loaded from the
				// database, a block split after analysis, or an architecture that does not populate
				// it). Read the block from the view instead.
				DataBuffer& buffer = instrData[i];
				if (buffer.GetLength() == 0)
					buffer = data->ReadBuffer(i->GetStart(), i->GetEnd() - i->GetStart());

				uint64_t blockStart = i->GetStart();
				size_t bufferLen = buffer.GetLength();
				if (addr < blockStart || (addr - blockStart) >= bufferLen)
				{
					function->AddInstruction(function->AddExpr(LLIL_UNDEF, 0, 0));
					logger->LogDebug("Instruction data not found, inserted LLIL_UNDEF at %#" PRIx64, addr);
					break;
				}

				size_t bufferOffset = static_cast<size_t>(addr - blockStart);
				len = bufferLen - bufferOffset;
				opcode = (const uint8_t*)buffer.GetDataAt(bufferOffset);
				if (!opcode)
				{
					function->AddInstruction(function->AddExpr(LLIL_UNDEF, 0, 0));
					logger->LogDebug("Instruction data not found, inserted LLIL_UNDEF at %#" PRIx64, addr);
					break;
				}
			}

			size_t instrCountBefore = function->GetInstructionCount();
			auto liftTarget = function;
			bool status = overrideLifter ? overrideLifter->LiftInstruction(i, cur, opcode, len, liftTarget)
				: i->GetArchitecture()->GetInstructionLowLevelIL(opcode, addr, len, *function);
			size_t instrCountAfter = liftTarget->GetInstructionCount();
			while (nextRelocation && nextRelocation->GetAddress() >= addr && nextRelocation->GetAddress() < addr + len)
			{
				if (data->IsOffsetExternSemantics(nextRelocation->GetTarget())
					&& !(overrideLifter && overrideLifter->IsNopOverride()))
				{
					int64_t operand = relocationHandler->GetOperandForExternalRelocation(
						opcode, addr, len, liftTarget, nextRelocation);
					if (operand != BN_NOCOERCE_EXTERN_PTR)
					{
						ApplyExternPointerForRelocation(
							operand, *liftTarget, liftTarget == function ? instrCountBefore : 0,
							instrCountAfter, nextRelocation, logger);
					}
				}
				nextRelocation = data->GetNextRelocation(nextRelocation->GetAddress() + 1, i->GetEnd());
			}
			if (overrideLifter && !overrideLifter->FinishInstruction(cur, addr + len, status, instrCountAfter))
				return false;

			// Conditional Call Support (Part 2)
			// Replace the emitted GOTO with a noreturn expression
			if (((instrCountAfter - instrCountBefore) >= 3)
				&& noReturnCalls.count(ArchAndAddr(i->GetArchitecture(), addr)))
			{
				for (size_t instrIndex = instrCountBefore; instrIndex < (instrCountAfter - 1); instrIndex++)
				{
					auto call = function->GetInstruction(instrIndex);
					if ((call.operation != LLIL_CALL) || (call.attributes & ILBranchOverride))
						continue;
					LowLevelILInstruction instr = function->GetInstruction(instrIndex + 1);
					if (instr.operation == LLIL_GOTO)
						function->ReplaceExpr(instr.exprIndex, function->AddExpr(LLIL_NORET, 0, 0));
				}
			}

			uint64_t prevAddr = addr;
			addr += len;

			context.CheckForInlinedCall(i, instrCountBefore, instrCountAfter, prevAddr, addr, opcode, len, indirectSource);

			// Indirect branch information informs when to translate non-standard returns into jumps
			if (auto lastInstr = instrCountAfter ? function->GetInstruction(instrCountAfter - 1) : LowLevelILInstruction();
					instrCountAfter && (lastInstr.operation == LLIL_RET) && !(lastInstr.attributes & ILBranchOverride)
					&& (function->HasIndirectBranches() || !function->GetFunction()->CanReturn().GetValue()))
			{
				auto addressSize = platform->GetAddressSize();
				lastInstr.Replace(function->SetRegister(addressSize, LLIL_TEMP(0), lastInstr.GetDestExpr().exprIndex));
				function->AddInstruction(function->Jump(function->Register(addressSize, LLIL_TEMP(0)), lastInstr));
				//lastInstr.Replace(m_liftedIL->Jump(lastInstr.GetDestExpr().exprIndex, lastInstr));
			}

			if (!status)
			{
				// Invalid instruction, emit undefined IL instruction
				function->AddInstruction(function->AddExpr(LLIL_UNDEF, 0, 0));
				logger->LogDebug("Invalid instruction, inserted LLIL_UNDEF at %#" PRIx64, addr);
				break;
			}
		}

		function->ClearIndirectBranches();

		// Support for contextual function returns. This is mainly used for ARM/Thumb with 'blx lr'. It's most common for this to be treated
		// as a function return, however it can also be a function call. For now this transform is described as follows:
		// 1) Architecture lifts a call instruction as LLIL_CALL with a branch type of FunctionReturn
		// 2) By default, contextualFunctionReturns is used to translate this to a LLIL_RET (conservative)
		// 3) Downstream analysis uses dataflow to validate the return target
		// 4) If the target is not the ReturnAddressValue, then we avoid the translation to a return and leave the instruction as a call
		if (LowLevelILInstruction prevInstr = function->GetInstruction(function->GetInstructionCount() - 1);
			(prevInstr.operation == LLIL_CALL) && !(prevInstr.attributes & ILBranchOverride))
		{
			if (auto itr = contextualReturns.find(ArchAndAddr(i->GetArchitecture(), prevInstr.address)); itr != contextualReturns.end() && itr->second)
				prevInstr.Replace(function->Return(prevInstr.GetDestExpr().exprIndex, prevInstr));
		}

		// If basic block does not end in a jump or undefined instruction, add jump to the next block
		size_t endInstrCount = function->GetInstructionCount();
		if (endInstrCount == beginInstrCount)
		{
			// Basic block must have instructions to be valid
			function->AddInstruction(function->AddExpr(LLIL_UNDEF, 0, 0));
			logger->LogDebug(
				"Basic block must have instructions to be valid, inserted LLIL_UNDEF at %#" PRIx64, i->GetStart());
		}
		else if ((i->GetOutgoingEdges().size() == 0) && !i->CanExit() && !i->IsFallThroughToFunction())
		{
			// Basic block does not exit
			function->AddInstruction(function->AddExpr(LLIL_NORET, 0, 0));
		}
		else
		{
			BNLowLevelILLabel* exitLabel = function->GetLabelForAddress(i->GetArchitecture(), i->GetEnd());
			if (exitLabel)
				function->AddInstruction(function->Goto(*exitLabel));
			else
			{
				size_t dest =
					function->AddExpr(LLIL_CONST_PTR, platform->GetAddressSize(), 0, i->GetEnd());
				function->AddInstruction(function->AddExpr(LLIL_JUMP, 0, 0, dest));
			}
		}
	}

	if (function->GetInstructionCount() == 0)
	{
		// If no instructions, make it undefined
		function->AddInstruction(function->AddExpr(LLIL_UNDEF, 0, 0));
		logger->LogDebug("No instructions found, inserted LLIL_UNDEF at %#" PRIx64,
			function->GetFunction()->GetStart());
	}

	function->Finalize();
	return true;
}


void FunctionLifterContext::CheckForInlinedCall(BasicBlock* block, size_t instrCountBefore, size_t instrCountAfter,
	uint64_t prevAddr, uint64_t addr, const uint8_t* opcode, size_t len,
	std::optional<pair<ArchAndAddr, ArchAndAddr>> indirectSource)
{
	// Check for direct inlined calls
	// TODO: Handle indirect calls where the address is constant
	if (instrCountAfter > instrCountBefore)
	{
		LowLevelILInstruction lastInstr = m_function->GetInstruction(instrCountAfter - 1);
		if ((lastInstr.operation == LLIL_JUMP) && (lastInstr.attributes & ILBranchOverride))
			return;
		if ((lastInstr.operation == LLIL_CALL || lastInstr.operation == LLIL_JUMP)
			&& (lastInstr.GetDestExpr().operation == LLIL_CONST || lastInstr.GetDestExpr().operation == LLIL_CONST_PTR))
		{
			InstructionInfo info;
			if (!block->GetArchitecture()->GetInstructionInfo(opcode, prevAddr, len, info))
				return;

			uint64_t target = lastInstr.GetDestExpr().GetConstant();
			Ref<Platform> platform =
				info.archTransitionByTargetAddr ? m_platform->GetAssociatedPlatformByAddress(target) : m_platform;
			if (!platform)
				return;

			// Avoid inline recursion
			if (m_inlinedCalls.count(target) != 0)
				return;

			Ref<Function> targetFunc = m_view->GetAnalysisFunction(platform, target);
			if (!targetFunc)
				return;

			auto inlineDuringAnalysis = targetFunc->GetInlinedDuringAnalysis().GetValue();
			if (inlineDuringAnalysis == DoNotInlineCall)
				return;

			// Must not be a conditional call.
			// TODO: Expand support to allow these.
			bool hasBranches = false;
			for (size_t instrIndex = instrCountBefore; instrIndex < instrCountAfter - 1; instrIndex++)
			{
				LowLevelILInstruction instr = m_function->GetInstruction(instrIndex);
				if (instr.operation == LLIL_IF || instr.operation == LLIL_GOTO)
				{
					hasBranches = true;
					break;
				}
			}
			if (hasBranches)
				return;

			// Get lifted IL for the target function
			m_inlinedCalls.insert(target);
			Ref<LowLevelILFunction> targetIL = GetForeignFunctionLiftedIL(targetFunc);
			m_inlinedCalls.erase(target);
			if (!targetIL)
			{
				// Lifting of inlined function failed, do not inline
				return;
			}

			// Replace call with a goto to the inlined code
			LowLevelILLabel start, end;
			m_function->MarkLabel(start);
			m_function->ReplaceExpr(lastInstr.exprIndex, m_function->Goto(start, lastInstr));

			set<uint32_t> returnAddressRegisters;
			for (size_t instrIndex = instrCountBefore; instrIndex < instrCountAfter - 1; instrIndex++)
			{
				LowLevelILInstruction instr = m_function->GetInstruction(instrIndex);
				if (instr.operation != LLIL_SET_REG)
					continue;

				// Call-like jumps may store the fallthrough address in any register, such as RISC-V jal t0.
				if (ConstantCompare(instr.GetSourceExpr<LLIL_SET_REG>(), addr))
					returnAddressRegisters.insert(instr.GetDestRegister<LLIL_SET_REG>());
			}
			bool hasCallSemantics = lastInstr.operation == LLIL_CALL
				|| (lastInstr.operation == LLIL_JUMP && !returnAddressRegisters.empty());

			// Copy the inlined code from the target function
			Ref<Architecture> callArch = block->GetArchitecture();
			auto blocks = PrepareToCopyForeignFunction(targetIL);
			auto unresolvedIndirectBranches = targetFunc->GetUnresolvedIndirectBranches();
			auto sourceLocation = inlineDuringAnalysis == InlineUsingCallAddress ? ILSourceLocation(lastInstr) : ILSourceLocation();
			set<uint32_t> unmodifiedReturnAddressRegisters = returnAddressRegisters;
			bool calleeReturnsThroughCallerReturnAddressRegister = false;
			for (auto& block : blocks)
			{
				for (size_t instrIndex = block->GetStart(); instrIndex < block->GetEnd(); instrIndex++)
				{
					// If the callee overwrites a caller-set return register, later jumps through it are not returns.
					RemoveWrittenReturnAddressRegisters(targetIL->GetInstruction(instrIndex), unmodifiedReturnAddressRegisters);
				}
			}
			for (auto& block : blocks)
			{
				for (size_t instrIndex = block->GetStart(); instrIndex < block->GetEnd(); instrIndex++)
				{
					// A callee ending in jr t0/ret t0 already returns through the caller's chosen link register.
					if (IsReturnAddressRegisterJumpOrReturn(
						targetIL->GetInstruction(instrIndex), unmodifiedReturnAddressRegisters))
						calleeReturnsThroughCallerReturnAddressRegister = true;
				}
			}

			if (hasCallSemantics && !calleeReturnsThroughCallerReturnAddressRegister)
			{
				// Set up return address according to the architecture
				uint32_t linkReg = m_platform->GetArchitecture()->GetLinkRegister();
				if (linkReg == BN_INVALID_REGISTER)
				{
					// No link register, push return address onto stack
					// XXX: hey, this is one of the things making bad datavars inside functions, look into this
					size_t addrSize = m_platform->GetAddressSize();
					ExprId pushExpr =
						m_function->Push(addrSize, m_function->ConstPointer(addrSize, addr, lastInstr), 0, lastInstr);
					m_function->SetExprAttributes(pushExpr, ILAllowDeadStoreElimination);
					m_function->AddInstruction(pushExpr);
				}
				else
				{
					// Set link register to return address
					BNRegisterInfo regInfo = m_platform->GetArchitecture()->GetRegisterInfo(linkReg);

					uint64_t addrToSet = addr;
					const auto& archName = block->GetArchitecture()->GetName();
					if ((archName == "thumb2") || (archName == "thumb2eb"))
						addrToSet |= 1;

					ExprId linkExpr = m_function->SetRegister(
						regInfo.size, linkReg, m_function->ConstPointer(regInfo.size, addrToSet, lastInstr), 0, lastInstr);
					m_function->SetExprAttributes(linkExpr, ILAllowDeadStoreElimination);
					m_function->AddInstruction(linkExpr);
				}
			}
			for (auto& block : blocks)
			{
				m_function->PrepareToCopyBlock(block);
				for (size_t instrIndex = block->GetStart(); instrIndex < block->GetEnd(); instrIndex++)
				{
					LowLevelILInstruction instr = targetIL->GetInstruction(instrIndex);
					ArchAndAddr loc(block->GetArchitecture(), instr.address);

					if (hasCallSemantics && instr.operation == LLIL_RET)
					{
						// If the instruction is a return, emit the computation of the target
						// location (it may affect the stack pointer) but go directly to the
						// return label instead of emitting a return instruction.
						// TODO: Handle architectures that don't use LLIL_RET and functions
						// that jump to the return address in nonstandard ways
						//m_liftedIL->AddInstruction(m_liftedIL->Jump(instr.GetDestExpr<LLIL_RET>().CopyTo(m_liftedIL), instr));
						m_function->AddInstruction(instr.GetDestExpr<LLIL_RET>().CopyTo(m_function, sourceLocation));
						m_function->AddInstruction(m_function->Goto(end, sourceLocation));
					}
					else if (hasCallSemantics && instr.operation == LLIL_JUMP
						&& (block->GetArchitecture() == callArch)
						&& (ConstantCompare(instr.GetDestExpr<LLIL_JUMP>(), addr)
							|| IsReturnAddressRegisterExpr(instr.GetDestExpr<LLIL_JUMP>(),
								unmodifiedReturnAddressRegisters)))
					{
						// Convert jumps back to fallthrough, including jr t0-style returns, into the inline continuation.
						m_function->AddInstruction(m_function->Goto(end, sourceLocation));
					}
					else if (hasCallSemantics && instr.operation == LLIL_JUMP
						&& block->GetOutgoingEdges().empty() && (unresolvedIndirectBranches.count(loc) == 0))
					{
						// Jump without outgoing edges in the graph, and it is not marked as having
						// unresolved branches, and this is the end of the function. This implies
						// that this is a tail call. Copy tail calls as a call followed by a goto to
						// the end of the inlined section. If the architecture places the return
						// address on the stack, ensure to pop it off before emitting the call, as
						// this implicitly places a return address onto the stack. We do not need
						// to worry about nested inlining here because that is already resolved at
						// this point.
						uint32_t linkReg = m_platform->GetArchitecture()->GetLinkRegister();
						if (linkReg == BN_INVALID_REGISTER)
						{
							size_t addrSize = m_platform->GetAddressSize();
							m_function->AddInstruction(m_function->Pop(addrSize, 0, sourceLocation));
						}
						m_function->AddInstruction(
							m_function->Call(instr.GetDestExpr<LLIL_JUMP>().CopyTo(m_function), sourceLocation));
						m_function->AddInstruction(m_function->Goto(end, sourceLocation));
					}
					else
					{
						if (indirectSource.has_value() && indirectSource->second == loc)
						{
							ArchAndAddr cur(indirectSource->first);
							if (auto brit = m_userIndirectBranches.find(cur); brit != m_userIndirectBranches.end())
							{
								const auto& s = brit->second;
								m_function->SetIndirectBranches(std::vector<ArchAndAddr>(s.begin(), s.end()));
							}
							else if (auto brit = m_autoIndirectBranches.find(cur); brit != m_autoIndirectBranches.end())
							{
								const auto& s = brit->second;
								m_function->SetIndirectBranches(std::vector<ArchAndAddr>(s.begin(), s.end()));
							}

							m_function->SetCurrentAddress(loc.arch, loc.address);
						}

						// Other instructions are copied directly
						m_function->AddInstruction(instr.CopyTo(m_function, sourceLocation));
					}
				}
			}

			// Mark end of inlined code, execution will resume at the instruction following the call
			m_function->MarkLabel(end);
			*m_containsInlinedFunctions = true;
		}
	}
}


bool Architecture::DefaultLiftFunctionCallback(BNLowLevelILFunction* function, BNFunctionLifterContext* context)
{
	Ref func(new LowLevelILFunction(BNNewLowLevelILFunctionReference(function)));
	FunctionLifterContext flc(func, context);
	return DefaultLiftFunction(func, flc);
}
