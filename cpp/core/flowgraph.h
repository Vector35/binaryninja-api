#pragma once
#include "core/binaryninja_defs.h"

extern "C" {
	struct BNFlowGraph;
	struct BNLowLevelILFunction;
	struct BNMediumLevelILFunction;
	struct BNHighLevelILFunction;
	struct BNDisassemblySettings;
	struct BNFlowGraphLayoutRequest;
	struct BNBinaryView;

	struct BNPoint
	{
		float x;
		float y;
	};

	// The following edge styles map to Qt's Qt::PenStyle enumeration
	enum BNEdgePenStyle
	{
		NoPen = 0,           // no line at all.
		SolidLine = 1,       // A plain line (default)
		DashLine = 2,        // Dashes separated by a few pixels.
		DotLine = 3,         // Dots separated by a few pixels.
		DashDotLine = 4,     // Alternate dots and dashes.
		DashDotDotLine = 5,  // One dash, two dots, one dash, two dots.
	};

	struct BNEdgeStyle
	{
		BNEdgePenStyle style;
		size_t width;
		BNThemeColor color;
	};

	struct BNFlowGraphNode;
	struct BNFlowGraphEdge
	{
		BNBranchType type;
		BNFlowGraphNode* target;
		BNPoint* points;
		size_t pointCount;
		bool backEdge;
		BNEdgeStyle style;
	};


	enum BNFlowGraphOption
	{
		FlowGraphUsesBlockHighlights,
		FlowGraphUsesInstructionHighlights,
		FlowGraphIncludesUserComments,
		FlowGraphAllowsPatching,
		FlowGraphAllowsInlineInstructionEditing,
		FlowGraphShowsSecondaryRegisterHighlighting
	};


	struct BNCustomFlowGraph
	{
		void* context;
		void (*prepareForLayout)(void* ctxt);
		void (*populateNodes)(void* ctxt);
		void (*completeLayout)(void* ctxt);
		BNFlowGraph* (*update)(void* ctxt);
		void (*freeObject)(void* ctxt);
		void (*externalRefTaken)(void* ctxt);
		void (*externalRefReleased)(void* ctxt);
	};

	// Flow graphs
	BINARYNINJACOREAPI BNFlowGraph* BNCreateFlowGraph();
	BINARYNINJACOREAPI BNFlowGraph* BNCreateFunctionGraph(
		BNFunction* func, BNFunctionGraphType type, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNFlowGraph* BNCreateLowLevelILFunctionGraph(
		BNLowLevelILFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNFlowGraph* BNCreateMediumLevelILFunctionGraph(
		BNMediumLevelILFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNFlowGraph* BNCreateHighLevelILFunctionGraph(
		BNHighLevelILFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNFlowGraph* BNCreateCustomFlowGraph(BNCustomFlowGraph* callbacks);
	BINARYNINJACOREAPI BNFlowGraph* BNNewFlowGraphReference(BNFlowGraph* graph);
	BINARYNINJACOREAPI void BNFreeFlowGraph(BNFlowGraph* graph);
	BINARYNINJACOREAPI BNFunction* BNGetFunctionForFlowGraph(BNFlowGraph* graph);
	BINARYNINJACOREAPI void BNSetFunctionForFlowGraph(BNFlowGraph* graph, BNFunction* func);
	BINARYNINJACOREAPI BNBinaryView* BNGetViewForFlowGraph(BNFlowGraph* graph);
	BINARYNINJACOREAPI void BNSetViewForFlowGraph(BNFlowGraph* graph, BNBinaryView* view);

	BINARYNINJACOREAPI int BNGetHorizontalFlowGraphNodeMargin(BNFlowGraph* graph);
	BINARYNINJACOREAPI int BNGetVerticalFlowGraphNodeMargin(BNFlowGraph* graph);
	BINARYNINJACOREAPI void BNSetFlowGraphNodeMargins(BNFlowGraph* graph, int horiz, int vert);

	BINARYNINJACOREAPI BNFlowGraphLayoutRequest* BNStartFlowGraphLayout(
		BNFlowGraph* graph, void* ctxt, void (*func)(void* ctxt));
	BINARYNINJACOREAPI bool BNIsFlowGraphLayoutComplete(BNFlowGraph* graph);
	BINARYNINJACOREAPI BNFlowGraphLayoutRequest* BNNewFlowGraphLayoutRequestReference(BNFlowGraphLayoutRequest* layout);
	BINARYNINJACOREAPI void BNFreeFlowGraphLayoutRequest(BNFlowGraphLayoutRequest* layout);
	BINARYNINJACOREAPI bool BNIsFlowGraphLayoutRequestComplete(BNFlowGraphLayoutRequest* layout);
	BINARYNINJACOREAPI BNFlowGraph* BNGetGraphForFlowGraphLayoutRequest(BNFlowGraphLayoutRequest* layout);
	BINARYNINJACOREAPI void BNAbortFlowGraphLayoutRequest(BNFlowGraphLayoutRequest* graph);
	BINARYNINJACOREAPI bool BNIsILFlowGraph(BNFlowGraph* graph);
	BINARYNINJACOREAPI bool BNIsLowLevelILFlowGraph(BNFlowGraph* graph);
	BINARYNINJACOREAPI bool BNIsMediumLevelILFlowGraph(BNFlowGraph* graph);
	BINARYNINJACOREAPI bool BNIsHighLevelILFlowGraph(BNFlowGraph* graph);
	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetFlowGraphLowLevelILFunction(BNFlowGraph* graph);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetFlowGraphMediumLevelILFunction(BNFlowGraph* graph);
	BINARYNINJACOREAPI BNHighLevelILFunction* BNGetFlowGraphHighLevelILFunction(BNFlowGraph* graph);
	BINARYNINJACOREAPI void BNSetFlowGraphLowLevelILFunction(BNFlowGraph* graph, BNLowLevelILFunction* func);
	BINARYNINJACOREAPI void BNSetFlowGraphMediumLevelILFunction(BNFlowGraph* graph, BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI void BNSetFlowGraphHighLevelILFunction(BNFlowGraph* graph, BNHighLevelILFunction* func);

	struct BNFlowGraphNode;
	struct BNFlowGraphEdge;
	BINARYNINJACOREAPI BNFlowGraphNode** BNGetFlowGraphNodes(BNFlowGraph* graph, size_t* count);
	BINARYNINJACOREAPI BNFlowGraphNode* BNGetFlowGraphNode(BNFlowGraph* graph, size_t i);
	BINARYNINJACOREAPI BNFlowGraphNode** BNGetFlowGraphNodesInRegion(
		BNFlowGraph* graph, int left, int top, int right, int bottom, size_t* count);
	BINARYNINJACOREAPI void BNFreeFlowGraphNodeList(BNFlowGraphNode** nodes, size_t count);
	BINARYNINJACOREAPI bool BNFlowGraphHasNodes(BNFlowGraph* graph);
	BINARYNINJACOREAPI size_t BNAddFlowGraphNode(BNFlowGraph* graph, BNFlowGraphNode* node);

	BINARYNINJACOREAPI int BNGetFlowGraphWidth(BNFlowGraph* graph);
	BINARYNINJACOREAPI int BNGetFlowGraphHeight(BNFlowGraph* graph);

	BINARYNINJACOREAPI BNFlowGraphNode* BNCreateFlowGraphNode(BNFlowGraph* graph);
	BINARYNINJACOREAPI BNFlowGraphNode* BNNewFlowGraphNodeReference(BNFlowGraphNode* node);
	BINARYNINJACOREAPI void BNFreeFlowGraphNode(BNFlowGraphNode* node);
	BINARYNINJACOREAPI BNFlowGraph* BNGetFlowGraphNodeOwner(BNFlowGraphNode* node);

	BINARYNINJACOREAPI BNBasicBlock* BNGetFlowGraphBasicBlock(BNFlowGraphNode* node);
	BINARYNINJACOREAPI void BNSetFlowGraphBasicBlock(BNFlowGraphNode* node, BNBasicBlock* block);
	BINARYNINJACOREAPI int BNGetFlowGraphNodeX(BNFlowGraphNode* node);
	BINARYNINJACOREAPI int BNGetFlowGraphNodeY(BNFlowGraphNode* node);
	BINARYNINJACOREAPI int BNGetFlowGraphNodeWidth(BNFlowGraphNode* node);
	BINARYNINJACOREAPI int BNGetFlowGraphNodeHeight(BNFlowGraphNode* node);

	BINARYNINJACOREAPI BNDisassemblyTextLine* BNGetFlowGraphNodeLines(BNFlowGraphNode* node, size_t* count);
	BINARYNINJACOREAPI void BNSetFlowGraphNodeLines(BNFlowGraphNode* node, BNDisassemblyTextLine* lines, size_t count);
	BINARYNINJACOREAPI BNFlowGraphEdge* BNGetFlowGraphNodeOutgoingEdges(BNFlowGraphNode* node, size_t* count);
	BINARYNINJACOREAPI BNFlowGraphEdge* BNGetFlowGraphNodeIncomingEdges(BNFlowGraphNode* node, size_t* count);
	BINARYNINJACOREAPI void BNFreeFlowGraphNodeEdgeList(BNFlowGraphEdge* edges, size_t count);
	BINARYNINJACOREAPI void BNAddFlowGraphNodeOutgoingEdge(
		BNFlowGraphNode* node, BNBranchType type, BNFlowGraphNode* target, BNEdgeStyle edgeStyle);

	BINARYNINJACOREAPI BNHighlightColor BNGetFlowGraphNodeHighlight(BNFlowGraphNode* node);
	BINARYNINJACOREAPI void BNSetFlowGraphNodeHighlight(BNFlowGraphNode* node, BNHighlightColor color);

	BINARYNINJACOREAPI void BNFinishPrepareForLayout(BNFlowGraph* graph);

	BINARYNINJACOREAPI bool BNFlowGraphUpdateQueryMode(BNFlowGraph* graph);
	BINARYNINJACOREAPI bool BNFlowGraphHasUpdates(BNFlowGraph* graph);

	BINARYNINJACOREAPI BNFlowGraph* BNUpdateFlowGraph(BNFlowGraph* graph);

	BINARYNINJACOREAPI void BNSetFlowGraphOption(BNFlowGraph* graph, BNFlowGraphOption option, bool value);
	BINARYNINJACOREAPI bool BNIsFlowGraphOptionSet(BNFlowGraph* graph, BNFlowGraphOption option);

	BINARYNINJACOREAPI bool BNIsNodeValidForFlowGraph(BNFlowGraph* graph, BNFlowGraphNode* node);
}