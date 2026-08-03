#pragma once

#include "binaryninjaapi.h"

#include "third_party/zynamics/bindiff/call_graph.h"
#include "third_party/zynamics/bindiff/flow_graph.h"
#include "third_party/zynamics/bindiff/reader.h"

#include <third_party/zynamics/binexport/virtual_memory.h>
#include <functional>
#include <string>

class BinDiffView
{
public:
	security::bindiff::CallGraph m_callGraph;
	security::bindiff::FlowGraphs m_flowGraphs;
	security::bindiff::FlowGraphInfos m_flowGraphInfos;

	AddressSpace m_addressSpace;

	BinDiffView() = default;

	static std::unique_ptr<BinDiffView> FromFilePath(const std::string& filePath);

	// Generate a view from the given node, the nodes view must be available before calling.
	static std::unique_ptr<BinDiffView> FromSessionNode(
		BinaryNinja::SimilaritySessionNode& node, const std::function<bool(double)>& progress);
};
