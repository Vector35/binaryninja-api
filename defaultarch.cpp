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


static bool IsConstantPointer(LowLevelILInstruction expr, uint64_t value)
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
						if (data->IsOffsetExternSemantics(info.branchTarget[i]))
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
						if (data->IsOffsetExternSemantics(info.branchTarget[i]))
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
		logger->LogWarn("Unable to find const or const_ptr in expresssion @ %08x:%d", il.GetCurrentAddress(), start);
		return;
	}
	offset = offset - relocation->GetTarget();
	il.ReplaceExpr(id, il.ExternPointer(size, relocation->GetTarget(), offset));
}


bool Architecture::DefaultLiftFunction(LowLevelILFunction* function, FunctionLifterContext& context)
{
	std::unique_ptr<FastBasicBlockMap<DataBuffer>> instrData;
	Ref<BinaryView> data = context.GetView();
	Ref<Logger> logger = context.GetLogger();
	Ref<Platform> platform = context.GetPlatform();
	std::set<ArchAndAddr> noReturnCalls = context.GetNoReturnCalls();
	std::vector<Ref<BasicBlock>> blocks = context.GetBasicBlocks();
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
			const uint8_t* opcode;

			if (i->HasInstructionData())
			{
				opcode = i->GetInstructionData(addr, &len);

				if (len == 0)
				{
					// Instruction data not found, emit undefined IL instruction
					function->AddInstruction(function->AddExpr(LLIL_UNDEF, 0, 0));
					logger->LogDebug("Instruction data not found, inserted LLIL_UNDEF at %#" PRIx64, addr);
					break;
				}
			}
			else
			{
				if (!instrData)
					instrData = std::make_unique<FastBasicBlockMap<DataBuffer>>(blocks);

				DataBuffer& buffer = (*instrData)[i];
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
			bool status = i->GetArchitecture()->GetInstructionLowLevelIL(opcode, addr, len, *function);
			size_t instrCountAfter = function->GetInstructionCount();
			while (nextRelocation && nextRelocation->GetAddress() >= addr && nextRelocation->GetAddress() < addr + len)
			{
				if (data->IsOffsetExternSemantics(nextRelocation->GetTarget()))
				{
					int64_t operand = relocationHandler->GetOperandForExternalRelocation(
						opcode, addr, len, function, nextRelocation);
					if (operand != BN_NOCOERCE_EXTERN_PTR)
					{
						ApplyExternPointerForRelocation(
							operand, *function, instrCountBefore, instrCountAfter, nextRelocation, logger);
					}
				}
				nextRelocation = data->GetNextRelocation(nextRelocation->GetAddress() + 1, i->GetEnd());
			}

			// Conditional Call Support (Part 2)
			// Replace the emitted GOTO with a noreturn expression
			if (((instrCountAfter - instrCountBefore) >= 3)
				&& noReturnCalls.count(ArchAndAddr(i->GetArchitecture(), addr)))
			{
				for (size_t instrIndex = instrCountBefore; instrIndex < (instrCountAfter - 1); instrIndex++)
				{
					if (function->GetInstruction(instrIndex).operation != LLIL_CALL)
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
			if (auto lastInstr = function->GetInstruction(instrCountAfter - 1); (lastInstr.operation == LLIL_RET)
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
		if (LowLevelILInstruction prevInstr = function->GetInstruction(function->GetInstructionCount() - 1); prevInstr.operation == LLIL_CALL)
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

				if (IsConstantPointer(instr.GetSourceExpr<LLIL_SET_REG>(), addr))
					returnAddressRegisters.insert(instr.GetDestRegister<LLIL_SET_REG>());
			}

			if (lastInstr.operation == LLIL_CALL && returnAddressRegisters.empty())
			{
				// Set up return address according to the architecture
				// TODO: Handle architectures that use a nonstandard way of calling functions
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
					if (block->GetArchitecture()->GetName() == "thumb2")
						addrToSet |= 1; // XXX: hack moved here from lowlevelilfunction.cpp

					ExprId linkExpr = m_function->SetRegister(
						regInfo.size, linkReg, m_function->ConstPointer(regInfo.size, addrToSet, lastInstr), 0, lastInstr);
					m_function->SetExprAttributes(linkExpr, ILAllowDeadStoreElimination);
					m_function->AddInstruction(linkExpr);
				}
			}

			// Copy the inlined code from the target function
			Ref<Architecture> callArch = block->GetArchitecture();
			auto blocks = PrepareToCopyForeignFunction(targetIL);
			auto unresolvedIndirectBranches = targetFunc->GetUnresolvedIndirectBranches();
			auto sourceLocation = inlineDuringAnalysis == InlineUsingCallAddress ? ILSourceLocation(lastInstr) : ILSourceLocation();
			for (auto& block : blocks)
			{
				m_function->PrepareToCopyBlock(block);
				for (size_t instrIndex = block->GetStart(); instrIndex < block->GetEnd(); instrIndex++)
				{
					LowLevelILInstruction instr = targetIL->GetInstruction(instrIndex);
					ArchAndAddr loc(block->GetArchitecture(), instr.address);

					if (lastInstr.operation == LLIL_CALL && instr.operation == LLIL_RET)
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
					else if (lastInstr.operation == LLIL_CALL && instr.operation == LLIL_JUMP
						&& (block->GetArchitecture() == callArch)
						&& (IsConstantPointer(instr.GetDestExpr<LLIL_JUMP>(), addr)
							|| IsReturnAddressRegisterExpr(instr.GetDestExpr<LLIL_JUMP>(), returnAddressRegisters)))
					{
						m_function->AddInstruction(m_function->Goto(end, sourceLocation));
					}
					else if (lastInstr.operation == LLIL_CALL && instr.operation == LLIL_JUMP
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
