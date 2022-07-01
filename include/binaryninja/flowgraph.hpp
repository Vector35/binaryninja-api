#pragma once
#include <map>
#include <string>
#include <vector>

#include "refcount.hpp"
#include "binaryninjacore/flowgraph.h"

namespace BinaryNinja {
	class FlowGraph;
	class BasicBlock;
	class Function;
	class BinaryView;
	struct LowLevelILFunction;
	struct MediumLevelILFunction;
	struct HighLevelILFunction;
	struct DisassemblyTextLine;

	class FlowGraphLayoutRequest : public RefCountObject
	{
		BNFlowGraphLayoutRequest* m_object;
		std::function<void()> m_completeFunc;

		static void CompleteCallback(void* ctxt);

	  public:
		FlowGraphLayoutRequest(FlowGraph* graph, const std::function<void()>& completeFunc);
		virtual ~FlowGraphLayoutRequest();

		BNFlowGraphLayoutRequest* GetObject() const { return m_object; }

		Ref<FlowGraph> GetGraph() const;
		bool IsComplete() const;
		void Abort();
	};

	class FlowGraphNode;
	class FlowGraph : public CoreRefCountObject<BNFlowGraph, BNNewFlowGraphReference, BNFreeFlowGraph>
	{
		std::map<BNFlowGraphNode*, Ref<FlowGraphNode>> m_cachedNodes;

		static void PrepareForLayoutCallback(void* ctxt);
		static void PopulateNodesCallback(void* ctxt);
		static void CompleteLayoutCallback(void* ctxt);
		static BNFlowGraph* UpdateCallback(void* ctxt);
		static void FreeObjectCallback(void* ctxt);

	  protected:
		bool m_queryMode = false;

		FlowGraph(BNFlowGraph* graph);

		void FinishPrepareForLayout();
		virtual void PrepareForLayout();
		virtual void PopulateNodes();
		virtual void CompleteLayout();

	  public:
		FlowGraph();

		Ref<Function> GetFunction() const;
		Ref<BinaryView> GetView() const;
		void SetFunction(Function* func);
		void SetView(BinaryView* view);

		int GetHorizontalNodeMargin() const;
		int GetVerticalNodeMargin() const;
		void SetNodeMargins(int horiz, int vert);

		Ref<FlowGraphLayoutRequest> StartLayout(const std::function<void()>& func);
		bool IsLayoutComplete();

		std::vector<Ref<FlowGraphNode>> GetNodes();
		Ref<FlowGraphNode> GetNode(size_t i);
		bool HasNodes() const;
		size_t AddNode(FlowGraphNode* node);

		int GetWidth() const;
		int GetHeight() const;
		std::vector<Ref<FlowGraphNode>> GetNodesInRegion(int left, int top, int right, int bottom);

		bool IsILGraph() const;
		bool IsLowLevelILGraph() const;
		bool IsMediumLevelILGraph() const;
		bool IsHighLevelILGraph() const;
		Ref<LowLevelILFunction> GetLowLevelILFunction() const;
		Ref<MediumLevelILFunction> GetMediumLevelILFunction() const;
		Ref<HighLevelILFunction> GetHighLevelILFunction() const;
		void SetLowLevelILFunction(LowLevelILFunction* func);
		void SetMediumLevelILFunction(MediumLevelILFunction* func);
		void SetHighLevelILFunction(HighLevelILFunction* func);

		void Show(const std::string& title);

		virtual bool HasUpdates() const;

		virtual Ref<FlowGraph> Update();

		void SetOption(BNFlowGraphOption option, bool value = true);
		bool IsOptionSet(BNFlowGraphOption option);
	};

	struct FlowGraphEdge
	{
		BNBranchType type;
		Ref<FlowGraphNode> target;
		std::vector<BNPoint> points;
		bool backEdge;
		BNEdgeStyle style;
	};

	class FlowGraphNode : public CoreRefCountObject<BNFlowGraphNode, BNNewFlowGraphNodeReference, BNFreeFlowGraphNode>
	{
		std::vector<DisassemblyTextLine> m_cachedLines;
		std::vector<FlowGraphEdge> m_cachedEdges, m_cachedIncomingEdges;
		bool m_cachedLinesValid, m_cachedEdgesValid, m_cachedIncomingEdgesValid;

	  public:
		FlowGraphNode(FlowGraph* graph);
		FlowGraphNode(BNFlowGraphNode* node);

		Ref<FlowGraph> GetGraph() const;
		Ref<BasicBlock> GetBasicBlock() const;
		void SetBasicBlock(BasicBlock* block);
		int GetX() const;
		int GetY() const;
		int GetWidth() const;
		int GetHeight() const;

		const std::vector<DisassemblyTextLine>& GetLines();
		void SetLines(const std::vector<DisassemblyTextLine>& lines);
		const std::vector<FlowGraphEdge>& GetOutgoingEdges();
		const std::vector<FlowGraphEdge>& GetIncomingEdges();
		void AddOutgoingEdge(BNBranchType type, FlowGraphNode* target, BNEdgeStyle edgeStyle = BNEdgeStyle());

		BNHighlightColor GetHighlight() const;
		void SetHighlight(const BNHighlightColor& color);

		bool IsValidForGraph(FlowGraph* graph) const;
	};

	class CoreFlowGraph : public FlowGraph
	{
	  public:
		CoreFlowGraph(BNFlowGraph* graph);
		virtual bool HasUpdates() const override;
		virtual Ref<FlowGraph> Update() override;
	};
}