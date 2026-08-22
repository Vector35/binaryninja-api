#include "diffview.h"

#include "processor.h"

#include <third_party/zynamics/bindiff/differ.h>

BinDiffView::~BinDiffView()
{
	security::bindiff::DeleteFlowGraphs(&m_flowGraphs);
}

std::unique_ptr<BinDiffView> BinDiffView::FromFilePath(const std::string& filePath)
{
	auto view = std::make_unique<BinDiffView>();
	security::bindiff::Instruction::Cache instrCache;
	auto status = security::bindiff::Read(
		filePath, &view->m_callGraph, &view->m_flowGraphs, &view->m_flowGraphInfos, &instrCache);
	if (!status.ok())
	{
		BinaryNinja::LogErrorF("Failed to read bindiff data from {}: {}", filePath, status.message());
		return nullptr;
	}
	return view;
}

std::unique_ptr<BinDiffView> BinDiffView::FromSessionNode(
	BinaryNinja::SimilaritySessionNode& node, const std::function<bool(double)>& progress)
{
	if (!progress(0.0))
		return nullptr;
	// NOTE: The view is always available during visitation.
	BinDiffProcessor processor(*node.GetView());
	// BinDiff looks at the call graph of the binary so we actually need to construct the view from all known entities
	// not just the ones we expect to visit (think process vs. matching).
	const auto entities = node.GetEntities();
	for (size_t i = 0; i < entities.size(); ++i)
	{
		if (((i & 0xff) == 0) && !progress(0.6 * static_cast<double>(i) / entities.size()))
			return nullptr;
		const auto entity = entities[i];
		const auto entityInfo = node.GetEntity(entity);
		if (!entityInfo || entityInfo->type != SimilarityEntityFunction)
			continue;
		BinaryNinja::Ref<BinaryNinja::Function> function = node.GetEntityFunction(entity);
		if (function)
			processor.AddFunction(*function);
	}
	BinaryNinja::Ref<BinaryNinja::TemporaryFile> tmpFile = new BinaryNinja::TemporaryFile();
	if (!processor.Process(tmpFile->GetPath(), [&](double value) { return progress(0.6 + 0.35 * value); }))
		return nullptr;
	auto viewResult = FromFilePath(tmpFile->GetPath());
	if (!progress(1.0))
		return nullptr;
	return viewResult;
}
