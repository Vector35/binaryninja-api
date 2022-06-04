#pragma once
#include "binaryninja_defs.h"

extern "C" {
	struct BNBasicBlock;
	struct BNFunction;
	struct BNDisassemblySettings;
	struct BNArchitecture;
	struct BNLowLevelILFunction;
	struct BNMediumLevelILFunction;
	struct BNHighLevelILFunction;

	enum BNDisassemblyOption
	{
		ShowAddress = 0,
		ShowOpcode = 1,
		ExpandLongOpcode = 2,
		ShowVariablesAtTopOfGraph = 3,
		ShowVariableTypesWhenAssigned = 4,
		ShowCallParameterNames = 6,
		ShowRegisterHighlight = 7,
		ShowFunctionAddress = 8,
		ShowFunctionHeader = 9,

		// Linear disassembly options
		GroupLinearDisassemblyFunctions = 64,
		HighLevelILLinearDisassembly = 65,
		WaitForIL = 66,
		IndentHLILBody = 67,

		// Debugging options
		ShowFlagUsage = 128,
		ShowStackPointer = 129
	};

	struct BNBasicBlockEdge
	{
		BNBranchType type;
		BNBasicBlock* target;
		bool backEdge;
		bool fallThrough;
	};

	BINARYNINJACOREAPI void BNFreeDisassemblyTextLines(BNDisassemblyTextLine* lines, size_t count);

 	BINARYNINJACOREAPI BNBasicBlock* BNNewBasicBlockReference(BNBasicBlock* block);
	BINARYNINJACOREAPI void BNFreeBasicBlock(BNBasicBlock* block);
	BINARYNINJACOREAPI BNBasicBlock** BNGetFunctionBasicBlockList(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI void BNFreeBasicBlockList(BNBasicBlock** blocks, size_t count);

	BINARYNINJACOREAPI BNDisassemblySettings* BNCreateDisassemblySettings(void);
	BINARYNINJACOREAPI BNDisassemblySettings* BNNewDisassemblySettingsReference(BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNDisassemblySettings* BNDuplicateDisassemblySettings(BNDisassemblySettings* settings);
	BINARYNINJACOREAPI void BNFreeDisassemblySettings(BNDisassemblySettings* settings);

	BINARYNINJACOREAPI bool BNIsDisassemblySettingsOptionSet(
		BNDisassemblySettings* settings, BNDisassemblyOption option);
	BINARYNINJACOREAPI void BNSetDisassemblySettingsOption(
		BNDisassemblySettings* settings, BNDisassemblyOption option, bool state);

	BINARYNINJACOREAPI size_t BNGetDisassemblyWidth(BNDisassemblySettings* settings);
	BINARYNINJACOREAPI void BNSetDisassemblyWidth(BNDisassemblySettings* settings, size_t width);
	BINARYNINJACOREAPI size_t BNGetDisassemblyMaximumSymbolWidth(BNDisassemblySettings* settings);
	BINARYNINJACOREAPI void BNSetDisassemblyMaximumSymbolWidth(BNDisassemblySettings* settings, size_t width);
	BINARYNINJACOREAPI size_t BNGetDisassemblyGutterWidth(BNDisassemblySettings* settings);
	BINARYNINJACOREAPI void BNSetDisassemblyGutterWidth(BNDisassemblySettings* settings, size_t width);


	BINARYNINJACOREAPI BNFunction* BNGetBasicBlockFunction(BNBasicBlock* block);
	BINARYNINJACOREAPI BNArchitecture* BNGetBasicBlockArchitecture(BNBasicBlock* block);
	BINARYNINJACOREAPI BNBasicBlock* BNGetBasicBlockSource(BNBasicBlock* block);
	BINARYNINJACOREAPI uint64_t BNGetBasicBlockStart(BNBasicBlock* block);
	BINARYNINJACOREAPI uint64_t BNGetBasicBlockEnd(BNBasicBlock* block);
	BINARYNINJACOREAPI uint64_t BNGetBasicBlockLength(BNBasicBlock* block);
	BINARYNINJACOREAPI BNBasicBlockEdge* BNGetBasicBlockOutgoingEdges(BNBasicBlock* block, size_t* count);
	BINARYNINJACOREAPI BNBasicBlockEdge* BNGetBasicBlockIncomingEdges(BNBasicBlock* block, size_t* count);
	BINARYNINJACOREAPI void BNFreeBasicBlockEdgeList(BNBasicBlockEdge* edges, size_t count);
	BINARYNINJACOREAPI bool BNBasicBlockHasUndeterminedOutgoingEdges(BNBasicBlock* block);
	BINARYNINJACOREAPI bool BNBasicBlockCanExit(BNBasicBlock* block);
	BINARYNINJACOREAPI void BNBasicBlockSetCanExit(BNBasicBlock* block, bool value);
	BINARYNINJACOREAPI bool BNBasicBlockHasInvalidInstructions(BNBasicBlock* block);
	BINARYNINJACOREAPI size_t BNGetBasicBlockIndex(BNBasicBlock* block);
	BINARYNINJACOREAPI BNBasicBlock** BNGetBasicBlockDominators(BNBasicBlock* block, size_t* count, bool post);
	BINARYNINJACOREAPI BNBasicBlock** BNGetBasicBlockStrictDominators(BNBasicBlock* block, size_t* count, bool post);
	BINARYNINJACOREAPI BNBasicBlock* BNGetBasicBlockImmediateDominator(BNBasicBlock* block, bool post);
	BINARYNINJACOREAPI BNBasicBlock** BNGetBasicBlockDominatorTreeChildren(
	    BNBasicBlock* block, size_t* count, bool post);
	BINARYNINJACOREAPI BNBasicBlock** BNGetBasicBlockDominanceFrontier(BNBasicBlock* block, size_t* count, bool post);
	BINARYNINJACOREAPI BNBasicBlock** BNGetBasicBlockIteratedDominanceFrontier(
	    BNBasicBlock** blocks, size_t incomingCount, size_t* outputCount);
	BINARYNINJACOREAPI bool BNIsILBasicBlock(BNBasicBlock* block);
	BINARYNINJACOREAPI bool BNIsLowLevelILBasicBlock(BNBasicBlock* block);
	BINARYNINJACOREAPI bool BNIsMediumLevelILBasicBlock(BNBasicBlock* block);
	BINARYNINJACOREAPI bool BNIsHighLevelILBasicBlock(BNBasicBlock* block);
	BINARYNINJACOREAPI BNFunctionGraphType BNGetBasicBlockFunctionGraphType(BNBasicBlock* block);
	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetBasicBlockLowLevelILFunction(BNBasicBlock* block);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetBasicBlockMediumLevelILFunction(BNBasicBlock* block);
	BINARYNINJACOREAPI BNHighLevelILFunction* BNGetBasicBlockHighLevelILFunction(BNBasicBlock* block);
	BINARYNINJACOREAPI bool BNGetBasicBlockInstructionContainingAddress(
	    BNBasicBlock* block, uint64_t addr, uint64_t* start);
	BINARYNINJACOREAPI BNBasicBlock* BNGetBasicBlockSourceBlock(BNBasicBlock* block);
	BINARYNINJACOREAPI void BNMarkBasicBlockAsRecentlyUsed(BNBasicBlock* block);
	BINARYNINJACOREAPI BNDisassemblyTextLine* BNGetBasicBlockDisassemblyText(
	    BNBasicBlock* block, BNDisassemblySettings* settings, size_t* count);

	BINARYNINJACOREAPI BNHighlightColor BNGetBasicBlockHighlight(BNBasicBlock* block);
	BINARYNINJACOREAPI void BNSetAutoBasicBlockHighlight(BNBasicBlock* block, BNHighlightColor color);
	BINARYNINJACOREAPI void BNSetUserBasicBlockHighlight(BNBasicBlock* block, BNHighlightColor color);
}