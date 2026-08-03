#include "provider.h"

#include "third_party/zynamics/bindiff/differ.h"
#include "third_party/zynamics/bindiff/match/context.h"
#include "third_party/zynamics/bindiff/match/call_graph.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <iterator>
#include <unordered_set>

using namespace BinaryNinja;

namespace {
	// TODO: Hilarious windows esq progress, will remove at some point but that can be done later.
	constexpr double ViewPreparationProgress = 0.4;
	constexpr double MatchingProgress = 0.59;

	SimilarityRangeAnnotation BlockAnnotation(Function& function, uint64_t address, BNSimilarityAnnotationType type)
	{
		const Ref<BasicBlock> block = function.GetBasicBlockAtAddress(function.GetArchitecture(), address);
		return {address, block ? block->GetEnd() : address + 1, type};
	}

	std::string GetFlowGraphName(const security::bindiff::FlowGraph& graph)
	{
		if (!graph.GetDemangledName().empty())
			return graph.GetDemangledName();
		return graph.GetName();
	}

	struct ProgressRange
	{
		double start;
		double length;

		double operator()(const double progress) const { return start + (length * std::clamp(progress, 0.0, 1.0)); }
	};

	ProgressRange EdgeProgressRange(SimilaritySessionNode& from, SimilaritySessionNode& to)
	{
		const auto incoming = to.GetIncomingEdges();
		const auto edge = std::ranges::lower_bound(incoming, from.GetId());
		const size_t edgeIndex = static_cast<size_t>(std::distance(incoming.begin(), edge));
		const double edgeLength = MatchingProgress / static_cast<double>(incoming.size());
		return {ViewPreparationProgress + (edgeLength * static_cast<double>(edgeIndex)), edgeLength};
	}
}  // namespace

Ref<SimilarityProvider> GoogleSimilarityProviderType::Create(Settings&)
{
	return new GoogleSimilarityProvider(this);
}

Ref<Settings> GoogleSimilarityProviderType::GetDefaultSettings()
{
	return Settings::Instance("googleSimilarityProvider");
}

GoogleSimilarityProvider::GoogleSimilarityProvider(SimilarityProviderType* type) : SimilarityProvider(type) {}

bool GoogleSimilarityProvider::VisitNodeEdge(SimilaritySessionNode& from, SimilaritySessionNode& to,
	SimilarityProviderResults& results, SimilaritySessionCompletion& completion)
{
	std::shared_ptr<ViewState> primaryState;
	std::shared_ptr<ViewState> secondaryState;
	{
		std::shared_lock viewLock(m_viewsMutex);
		const auto primary = m_views.find(to.GetId());
		const auto secondary = m_views.find(from.GetId());
		if ((primary == m_views.end()) || (secondary == m_views.end()))
			return true;
		primaryState = primary->second;
		secondaryState = secondary->second;
	}

	const SimilaritySessionCompletionQuery progressQuery {to.GetId(), GetId(), std::nullopt};
	const ProgressRange edgeProgress = EdgeProgressRange(from, to);
	if (completion.IsStopRequested())
		return false;
	completion.SetProgress(progressQuery, edgeProgress(0.0));

	const auto scheduled = to.GetScheduledEntities();
	const std::unordered_set<SimilarityEntityId> scheduledEntities(scheduled.begin(), scheduled.end());

	std::vector<PendingMatch> pendingMatches;
	{
		std::scoped_lock viewLocks(primaryState->mutex, secondaryState->mutex);
		BinDiffView& primaryView = *primaryState->view;
		BinDiffView& secondaryView = *secondaryState->view;
		security::bindiff::ResetMatches(&primaryView.m_flowGraphs);
		security::bindiff::ResetMatches(&secondaryView.m_flowGraphs);
		struct MatchReset
		{
			security::bindiff::FlowGraphs& primary;
			security::bindiff::FlowGraphs& secondary;
			~MatchReset()
			{
				security::bindiff::ResetMatches(&primary);
				security::bindiff::ResetMatches(&secondary);
			}
		} reset {primaryView.m_flowGraphs, secondaryView.m_flowGraphs};

		security::bindiff::FixedPoints fixedPoints;
		security::bindiff::MatchingContext context(primaryView.m_callGraph, secondaryView.m_callGraph,
			primaryView.m_flowGraphs, secondaryView.m_flowGraphs, fixedPoints);

		// TODO: Expose options for diffing.
		security::bindiff::Diff(&context, security::bindiff::GetDefaultMatchingSteps(),
			security::bindiff::GetDefaultMatchingStepsBasicBlock());
		if (completion.IsStopRequested())
			return false;
		completion.SetProgress(progressQuery, edgeProgress(0.7));
		pendingMatches.reserve(fixedPoints.size());

		size_t fixedPointIndex = 0;
		for (const auto& fixedPoint : fixedPoints)
		{
			if (completion.IsStopRequested())
				return false;
			const double similarity = fixedPoint.GetSimilarity();
			// Scaling here because we choose to keep the scoring and confidence in a 0-255 range.
			const double normalizedSimilarity = std::isfinite(similarity) ? std::clamp(similarity, 0.0, 1.0) : 0.0;
			const auto similarityScore = static_cast<uint8_t>(std::lround(normalizedSimilarity * 255));
			const Address primaryAddr = fixedPoint.GetPrimary()->GetEntryPointAddress();
			const Address secondaryAddr = fixedPoint.GetSecondary()->GetEntryPointAddress();
			const std::string primaryName = GetFlowGraphName(*fixedPoint.GetPrimary());
			const std::string secondaryName = GetFlowGraphName(*fixedPoint.GetSecondary());

			const SimilarityEntityId primaryId =
				to.CreateEntity({SimilarityEntityFunction, primaryAddr, primaryName});
			fixedPointIndex++;
			const double fixedPointProgress = static_cast<double>(fixedPointIndex) / fixedPoints.size();
			completion.SetProgress(progressQuery, edgeProgress(0.7 + (0.25 * fixedPointProgress)));
			if (!scheduledEntities.contains(primaryId))
				continue;
			const SimilarityEntityId secondaryId =
				from.CreateEntity({SimilarityEntityFunction, secondaryAddr, secondaryName});
			const SimilarityEntityRef primaryRef(to.GetId(), primaryId);
			const SimilarityEntityRef secondaryRef(from.GetId(), secondaryId);
			Ref<Function> primaryFunction = to.GetEntityFunction(primaryId);
			Ref<Function> secondaryFunction = from.GetEntityFunction(secondaryId);
			std::vector<RenderData::BlockComparison> primaryBlocks;
			std::vector<RenderData::BlockComparison> secondaryBlocks;
			for (const auto& blockMatch : fixedPoint.GetBasicBlockFixedPoints())
			{
				const auto primaryInstructions =
					fixedPoint.GetPrimary()->GetInstructions(blockMatch.GetPrimaryVertex());
				const auto secondaryInstructions =
					fixedPoint.GetSecondary()->GetInstructions(blockMatch.GetSecondaryVertex());
				const size_t matchedInstructions = blockMatch.GetInstructionMatches().size();
				const size_t primaryInstructionCount = primaryInstructions.second - primaryInstructions.first;
				const size_t secondaryInstructionCount = secondaryInstructions.second - secondaryInstructions.first;
				primaryBlocks.push_back({fixedPoint.GetPrimary()->GetAddress(blockMatch.GetPrimaryVertex()),
					primaryInstructionCount, secondaryInstructionCount, matchedInstructions});
				secondaryBlocks.push_back({fixedPoint.GetSecondary()->GetAddress(blockMatch.GetSecondaryVertex()),
					secondaryInstructionCount, primaryInstructionCount, matchedInstructions});
			}
			if (primaryFunction && secondaryFunction)
			{
				const auto& primaryGraph = fixedPoint.GetPrimary()->GetGraph();
				for (auto [vertex, end] = boost::vertices(primaryGraph); vertex != end; ++vertex)
				{
					if (!fixedPoint.GetPrimary()->GetFixedPoint(*vertex))
						primaryBlocks.push_back({fixedPoint.GetPrimary()->GetAddress(*vertex), 0, 0, std::nullopt});
				}
				const auto& secondaryGraph = fixedPoint.GetSecondary()->GetGraph();
				for (auto [vertex, end] = boost::vertices(secondaryGraph); vertex != end; ++vertex)
				{
					if (!fixedPoint.GetSecondary()->GetFixedPoint(*vertex))
						secondaryBlocks.push_back({fixedPoint.GetSecondary()->GetAddress(*vertex), 0, 0, std::nullopt});
				}
			}

			// TODO: Move this entirely into the render method, doing this will require us to do some more coordination but
			// TODO: it will definitely be cleaner and allow us to remove the above and below code.
			std::optional<RenderData> primaryRender;
			std::optional<RenderData> secondaryRender;
			if (primaryFunction && secondaryFunction)
			{
				primaryRender = RenderData {{{SimilarityAnnotationAdded, std::move(primaryBlocks)},
					{SimilarityAnnotationRemoved, secondaryBlocks}}};
				secondaryRender = RenderData {{{SimilarityAnnotationRemoved, std::move(secondaryBlocks)},
					{SimilarityAnnotationAdded, primaryRender->sources[0].blocks}}};
			}
			pendingMatches.push_back({{primaryRef, secondaryRef}, similarityScore, primaryName, secondaryName,
				std::move(primaryRender), std::move(secondaryRender)});
		}
		if (fixedPoints.empty())
			completion.SetProgress(progressQuery, edgeProgress(0.95));
	}

	for (const auto& match : pendingMatches)
	{
		const SimilarityResultId primaryResult =
			results.AddResult(match.key.primary, match.key.secondary, match.similarity, 255);
		const SimilarityResultId secondaryResult =
			results.AddResult(match.key.secondary, match.key.primary, match.similarity, 255);
		if (!primaryResult.Value() || !secondaryResult.Value())
			return false;
	}
	if (completion.IsStopRequested())
		return false;
	completion.SetProgress(progressQuery, edgeProgress(0.99));

	{
		std::lock_guard lock(m_dataMutex);
		std::erase_if(m_renderData, [&](const auto& entry) {
			const MatchKey& key = entry.first;
			if ((key.primary.nodeId == to.GetId()) && (key.secondary.nodeId == from.GetId()))
				return scheduledEntities.contains(key.primary.entityId);
			if ((key.primary.nodeId == from.GetId()) && (key.secondary.nodeId == to.GetId()))
				return scheduledEntities.contains(key.secondary.entityId);
			return false;
		});
		for (auto& match : pendingMatches)
		{
			m_entityNames.insert_or_assign(match.key.primary, std::move(match.primaryName));
			m_entityNames.insert_or_assign(match.key.secondary, std::move(match.secondaryName));
			if (match.primaryRender)
				m_renderData.insert_or_assign(match.key, std::move(*match.primaryRender));
			else
				m_renderData.erase(match.key);
			const MatchKey reverseKey {match.key.secondary, match.key.primary};
			if (match.secondaryRender)
				m_renderData.insert_or_assign(reverseKey, std::move(*match.secondaryRender));
			else
				m_renderData.erase(reverseKey);
		}
	}
	return true;
}

bool GoogleSimilarityProvider::VisitNode(
	SimilaritySessionNode& node, SimilarityProviderResults&, SimilaritySessionCompletion& completion)
{
	const auto progressQuery = SimilaritySessionCompletionQuery::ForNode(node.GetId()).WithProvider(GetId());
	const double progressScale = node.GetIncomingEdges().empty() ? 0.99 : ViewPreparationProgress;
	auto diffView = BinDiffView::FromSessionNode(node, [&](double progress) {
		completion.SetProgress(progressQuery, progressScale * progress);
		return !completion.IsStopRequested();
	});
	if (completion.IsStopRequested())
		return false;
	if (!diffView)
	{
		std::lock_guard lock(m_viewsMutex);
		m_views.erase(node.GetId());
		return true;
	}
	auto state = std::make_shared<ViewState>();
	state->view = std::shared_ptr<BinDiffView>(std::move(diffView));

	{
		std::lock_guard lock(m_viewsMutex);
		m_views.insert_or_assign(node.GetId(), std::move(state));
	}
	return true;
}

std::optional<std::pair<SimilarityEntityRef, SimilarityResult>> GoogleSimilarityProvider::FindResult(
	SimilaritySessionNode& node, SimilarityEntityId entity, SimilarityResultId result)
{
	const auto value = node.GetResult(result);
	if (!value || (value->providerId != GetId()))
		return std::nullopt;
	return std::make_pair(SimilarityEntityRef(node.GetId(), entity), *value);
}

Ref<SimilaritySessionNode> GoogleSimilarityProvider::FindNode(SimilaritySessionNode& node, SimilaritySessionNodeId id)
{
	if (id == node.GetId())
		return &node;
	for (const auto& candidate : node.GetIncomingNodes())
	{
		if (candidate->GetId() == id)
			return candidate;
	}
	for (const auto& candidate : node.GetOutgoingNodes())
	{
		if (candidate->GetId() == id)
			return candidate;
	}
	return nullptr;
}

std::optional<std::string> GoogleSimilarityProvider::GetName(
	SimilaritySessionNode& node, SimilarityEntityId entity, SimilarityResultId result)
{
	const auto match = FindResult(node, entity, result);
	if (!match)
		return std::nullopt;

	std::shared_lock lock(m_dataMutex);
	const auto name = m_entityNames.find(match->second.target);
	if ((name == m_entityNames.end()) || name->second.empty())
		return std::nullopt;
	return name->second;
}

void GoogleSimilarityProvider::Render(
	SimilaritySessionNode& node, SimilarityEntityId entity, SimilarityRenderContext& context, SimilarityResultId result)
{
	const auto match = FindResult(node, entity, result);
	if (!match)
		return;
	const Ref<SimilaritySessionNode> targetNode = FindNode(node, match->second.target.nodeId);
	if (!targetNode)
		return;
	const std::vector<Ref<Function>> functions {
		node.GetEntityFunction(match->first.entityId), targetNode->GetEntityFunction(match->second.target.entityId)};
	const std::array<SimilarityEntityRef, 2> entities {match->first, match->second.target};

	RenderData data;
	{
		std::shared_lock lock(m_dataMutex);
		const auto entry = m_renderData.find(MatchKey {match->first, match->second.target});
		if (entry == m_renderData.end())
			return;
		data = entry->second;
	}
	for (size_t i = 0; i < data.sources.size() && i < functions.size(); i++)
	{
		const auto& source = data.sources[i];
		const auto& function = functions[i];
		if (!function)
			continue;
		Ref<DiffRenderer> renderer = new DiffRenderer();
		for (const auto& block : source.blocks)
		{
			BNSimilarityAnnotationType type = source.unmatchedType;
			if (block.matchedInstructionCount)
			{
				if ((block.instructionCount == *block.matchedInstructionCount)
					&& (block.otherInstructionCount == *block.matchedInstructionCount))
					continue;
				type = SimilarityAnnotationChanged;
			}
			renderer->AddRangeAnnotation(BlockAnnotation(*function, block.address, type));
		}
		renderer->Render(context, *function, entities[i]);
	}
}
