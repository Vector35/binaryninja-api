#pragma once

#include "binaryninjacore.h"
#include "refcount.h"
#include <functional>
#include <map>
#include <string>
#include <vector>


namespace BinaryNinja
{
	class BasicBlock;
	class BinaryView;
	struct DisassemblyTextLine;
	class FlowGraph;
	class FlowGraphNode;
	class Function;
	class HighLevelILFunction;
	class LowLevelILFunction;
	class MediumLevelILFunction;

	/*!
		\ingroup flowgraph
	*/
	struct FlowGraphEdge
	{
		BNBranchType type;
		Ref<FlowGraphNode> target;
		std::vector<BNPoint> points;
		bool backEdge;
		BNEdgeStyle style;
	};

	/*!
		\ingroup flowgraph
	*/
	class FlowGraphNode : public CoreRefCountObject<BNFlowGraphNode, BNNewFlowGraphNodeReference, BNFreeFlowGraphNode>
	{
		std::vector<DisassemblyTextLine> m_cachedLines;
		std::vector<FlowGraphEdge> m_cachedEdges, m_cachedIncomingEdges;
		bool m_cachedLinesValid, m_cachedEdgesValid, m_cachedIncomingEdgesValid;

	  public:
		FlowGraphNode(FlowGraph* graph);
		FlowGraphNode(BNFlowGraphNode* node);

		/*! Get the FlowGraph associated with this node

			\return The FlowGraph associated with this node
		*/
		Ref<FlowGraph> GetGraph() const;

		/*! Get the Basic Block associated with this node

			\return The BasicBlock associated with this node
		*/
		Ref<BasicBlock> GetBasicBlock() const;

		/*! Set the Basic Block associated with this node

			\param block The BasicBlock associated with this node
		*/
		void SetBasicBlock(BasicBlock* block);

		/*! Flow graph block X position

			\return Flow graph block X position
		*/
		int GetX() const;

		/*! Flow graph block Y position

			\return Flow graph block Y position
		*/
		int GetY() const;

		/*! Flow graph block width

			\return Flow graph block width
		*/
		int GetWidth() const;

		/*! Flow graph block height

			\return Flow graph block height
		*/
		int GetHeight() const;

		/*! Get the list of DisassemblyTextLines for this graph node.

			\return The list of DisassemblyTextLines for this graph node.
		*/
		const std::vector<DisassemblyTextLine>& GetLines();

		/*! Set the list of DisassemblyTextLines for this graph node.

			\param lines The list of DisassemblyTextLines for this graph node.
		*/
		void SetLines(const std::vector<DisassemblyTextLine>& lines);

		/*! Get the list of outgoing edges for this flow graph node

			\return The list of outgoing edges for this flow graph node
		*/
		const std::vector<FlowGraphEdge>& GetOutgoingEdges();

		/*! Get the list of incoming edges for this flow graph node

			\return The list of incoming edges for this flow graph node
		*/
		const std::vector<FlowGraphEdge>& GetIncomingEdges();

		/*! Connects two flow graph nodes with an edge

			\param type Type of edge to add
			\param target Target node object
			\param edgeStyle
		 	\parblock
		 	Custom style for this edge.

		 	Styling for graph edge Branch Type must be set to UserDefinedBranch
		 	\endparblock
		*/
		void AddOutgoingEdge(BNBranchType type, FlowGraphNode* target, BNEdgeStyle edgeStyle = BNEdgeStyle());

		/*! Get the highlight color for the node

			\return The highlight color for the node
		*/
		BNHighlightColor GetHighlight() const;

		/*! Set the highlight color for the node

			\param color The highlight color for the node
		*/
		void SetHighlight(const BNHighlightColor& color);

		bool IsValidForGraph(FlowGraph* graph) const;
	};

	/*!
		\ingroup flowgraph
	*/
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

	/*! FlowGraph implements a directed flow graph to be shown in the UI. This class allows plugins to
			create custom flow graphs and render them in the UI using the flow graph report API.

	 	\ingroup flowgraph
	*/
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

		/*! Get the Function associated with this FlowGraph

			\return The Function associated with this FlowGraph
		*/
		Ref<Function> GetFunction() const;

		/*! Get the BinaryView associated with this FlowGraph

			\return The BinaryView associated with this FlowGraph
		*/
		Ref<BinaryView> GetView() const;

		/*! Set the Function associated with this FlowGraph

			\param func The Function associated with this FlowGraph
		*/
		void SetFunction(Function* func);

		/*! Set the BinaryView associated with this FlowGraph

			\param view The BinaryView associated with this FlowGraph
		*/
		void SetView(BinaryView* view);

		int GetHorizontalNodeMargin() const;
		int GetVerticalNodeMargin() const;
		void SetNodeMargins(int horiz, int vert);

		/*! Starts rendering a graph for display. Once a layout is complete, each node will contain
			coordinates and extents that can be used to render a graph with minimum additional computation.
			This function does not wait for the graph to be ready to display, but a callback can be provided
			to signal when the graph is ready.

			\param func Callback to execute once layout is complete.
			\return
		*/
		Ref<FlowGraphLayoutRequest> StartLayout(const std::function<void()>& func);

		/*! Check whether layout is complete

			\return Whether layout is complete
		*/
		bool IsLayoutComplete();

		/*! Get the list of nodes in the graph

			\return List of nodes in the graph
		*/
		std::vector<Ref<FlowGraphNode>> GetNodes();

		/*! Retrieve node by index

			\param i Index of the node to retrieve
			\return The flow graph node at that index
		*/
		Ref<FlowGraphNode> GetNode(size_t i);

		/*! Whether the FlowGraph has any nodes added

			\return Whether the FlowGraph has any nodes added
		*/
		bool HasNodes() const;

		/*! Add a node to this flowgraph

			\param node Node to be added.
			\return Index of the node
		*/
		size_t AddNode(FlowGraphNode* node);

		/*! Flow graph width

			\return Flow graph width
		*/
		int GetWidth() const;

		/*! Flow graph height

			\return Flow graph height
		*/
		int GetHeight() const;
		std::vector<Ref<FlowGraphNode>> GetNodesInRegion(int left, int top, int right, int bottom);

		/*! Whether this graph is representing IL.

			\return Whether this graph is representing IL.
		*/
		bool IsILGraph() const;

		/*! Whether this graph is representing Low Level IL.

			\return Whether this graph is representing Low Level IL.
		*/
		bool IsLowLevelILGraph() const;

		/*! Whether this graph is representing Medium Level IL.

			\return Whether this graph is representing Medium Level IL.
		*/
		bool IsMediumLevelILGraph() const;

		/*! Whether this graph is representing High Level IL.

			\return Whether this graph is representing High Level IL.
		*/
		bool IsHighLevelILGraph() const;

		/*! Get the associated Low Level IL Function

			\return The associated Low Level IL Function
		*/
		Ref<LowLevelILFunction> GetLowLevelILFunction() const;

		/*! Get the associated Medium Level IL Function

			\return The associated Medium Level IL Function
		*/
		Ref<MediumLevelILFunction> GetMediumLevelILFunction() const;

		/*! Get the associated High Level IL Function

			\return The associated High Level IL Function
		*/
		Ref<HighLevelILFunction> GetHighLevelILFunction() const;

		/*! Set the associated Low Level IL Function

			\param func The associated function
		*/
		void SetLowLevelILFunction(LowLevelILFunction* func);

		/*! Set the associated Medium Level IL Function

			\param func The associated function
		*/
		void SetMediumLevelILFunction(MediumLevelILFunction* func);

		/*! Set the associated High Level IL Function

			\param func The associated function
		*/
		void SetHighLevelILFunction(HighLevelILFunction* func);

		/*! Display a flowgraph with a given title.

			\param title Title for the flowgraph
		*/
		void Show(const std::string& title);

		virtual bool HasUpdates() const;

		virtual Ref<FlowGraph> Update();

		void SetOption(BNFlowGraphOption option, bool value = true);
		bool IsOptionSet(BNFlowGraphOption option);
	};

	/*!
		\ingroup flowgraph
	*/
	class CoreFlowGraph : public FlowGraph
	{
	  public:
		CoreFlowGraph(BNFlowGraph* graph);
		virtual bool HasUpdates() const override;
		virtual Ref<FlowGraph> Update() override;
	};

}
