#include "provider.h"

#include "third_party/zynamics/bindiff/differ.h"
#include "third_party/zynamics/bindiff/match/context.h"
#include "third_party/zynamics/bindiff/match/call_graph.h"
#include "third_party/zynamics/bindiff/match/flow_graph.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <iterator>
#include <limits>
#include <tuple>
#include <unordered_set>

using namespace BinaryNinja;

namespace {
	// TODO: Hilarious windows esq progress, will remove at some point but that can be done later.
	constexpr double ViewPreparationProgress = 0.4;
	constexpr double MatchingProgress = 0.59;

	void AddAnnotation(std::vector<SimilarityRangeAnnotation>& annotations, uint64_t start, uint64_t end,
		BNSimilarityAnnotationType type)
	{
		if (end > start)
			annotations.emplace_back(start, end, type);
	}

	void AddBlockAnnotation(std::vector<SimilarityRangeAnnotation>& annotations, Function& function, uint64_t address,
		BNSimilarityAnnotationType type)
	{
		const Ref<BasicBlock> block = function.GetBasicBlockAtAddress(function.GetArchitecture(), address);
		const uint64_t end = block ? block->GetEnd() :
			(address == std::numeric_limits<uint64_t>::max() ? address : address + 1);
		AddAnnotation(annotations, address, end, type);
	}

	void AddUnmatchedInstructionAnnotations(std::vector<SimilarityRangeAnnotation>& annotations, Function& function,
		const std::pair<security::bindiff::Instructions::const_iterator,
			security::bindiff::Instructions::const_iterator>& instructions,
		const std::unordered_set<const security::bindiff::Instruction*>& matched,
		BNSimilarityAnnotationType type)
	{
		for (auto instruction = instructions.first; instruction != instructions.second; ++instruction)
		{
			if (matched.contains(&*instruction))
				continue;
			const uint64_t start = instruction->GetAddress();
			auto next = std::next(instruction);
			uint64_t end = next != instructions.second ? next->GetAddress() : start;
			if (end <= start)
			{
				const Ref<BasicBlock> block =
					function.GetBasicBlockAtAddress(function.GetArchitecture(), start);
				end = block ? block->GetEnd() :
					(start == std::numeric_limits<uint64_t>::max() ? start : start + 1);
			}
			AddAnnotation(annotations, start, end, type);
		}
	}

	void NormalizeAnnotations(std::vector<SimilarityRangeAnnotation>& annotations)
	{
		std::ranges::sort(annotations, [](const auto& left, const auto& right) {
			return std::tie(left.start, left.end, left.type) < std::tie(right.start, right.end, right.type);
		});
		std::vector<SimilarityRangeAnnotation> normalized;
		for (const auto& annotation : annotations)
		{
			if (!normalized.empty() && (normalized.back().type == annotation.type)
				&& (annotation.start <= normalized.back().end))
			{
				normalized.back().end = std::max(normalized.back().end, annotation.end);
			}
			else
				normalized.push_back(annotation);
		}
		annotations = std::move(normalized);
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
			pendingMatches.push_back({{primaryRef, secondaryRef}, similarityScore, primaryName, secondaryName});
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
		const auto invalidatedMatch = [&](const MatchKey& key) {
			if ((key.primary.nodeId == to.GetId()) && (key.secondary.nodeId == from.GetId()))
				return scheduledEntities.contains(key.primary.entityId);
			if ((key.primary.nodeId == from.GetId()) && (key.secondary.nodeId == to.GetId()))
				return scheduledEntities.contains(key.secondary.entityId);
			return false;
		};
		std::erase_if(m_renderAnnotations, [&](const auto& entry) { return invalidatedMatch(entry.first); });
		std::erase_if(m_primaryMatches, invalidatedMatch);
		for (auto& match : pendingMatches)
		{
			m_entityNames.insert_or_assign(match.key.primary, std::move(match.primaryName));
			m_entityNames.insert_or_assign(match.key.secondary, std::move(match.secondaryName));
			m_primaryMatches.insert(match.key);
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
		{
			std::lock_guard lock(m_viewsMutex);
			m_views.erase(node.GetId());
		}
		{
			std::lock_guard lock(m_dataMutex);
			std::erase_if(m_renderAnnotations, [&node](const auto& entry) {
				return (entry.first.primary.nodeId == node.GetId()) || (entry.first.secondary.nodeId == node.GetId());
			});
		}
		return true;
	}
	auto state = std::make_shared<ViewState>();
	state->view = std::shared_ptr<BinDiffView>(std::move(diffView));

	{
		std::lock_guard lock(m_viewsMutex);
		m_views.insert_or_assign(node.GetId(), std::move(state));
	}
	{
		std::lock_guard lock(m_dataMutex);
		std::erase_if(m_renderAnnotations, [&node](const auto& entry) {
			return (entry.first.primary.nodeId == node.GetId()) || (entry.first.secondary.nodeId == node.GetId());
		});
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

std::optional<GoogleSimilarityProvider::RenderAnnotations> GoogleSimilarityProvider::BuildRenderAnnotations(
	SimilaritySessionNode& sourceNode, SimilarityEntityId sourceEntity, SimilaritySessionNode& targetNode,
	SimilarityEntityId targetEntity, bool sourceIsPrimary)
{
	const auto sourceInfo = sourceNode.GetEntity(sourceEntity);
	const auto targetInfo = targetNode.GetEntity(targetEntity);
	Ref<Function> sourceFunction = sourceNode.GetEntityFunction(sourceEntity);
	Ref<Function> targetFunction = targetNode.GetEntityFunction(targetEntity);
	if (!sourceInfo || !targetInfo || !sourceFunction || !targetFunction)
		return std::nullopt;

	std::shared_ptr<ViewState> sourceState;
	std::shared_ptr<ViewState> targetState;
	{
		std::shared_lock viewLock(m_viewsMutex);
		const auto source = m_views.find(sourceNode.GetId());
		const auto target = m_views.find(targetNode.GetId());
		if ((source == m_views.end()) || (target == m_views.end()))
			return std::nullopt;
		sourceState = source->second;
		targetState = target->second;
	}

	std::scoped_lock viewLocks(sourceState->mutex, targetState->mutex);
	BinDiffView& sourceView = *sourceState->view;
	BinDiffView& targetView = *targetState->view;
	BinDiffView& primaryView = sourceIsPrimary ? sourceView : targetView;
	BinDiffView& secondaryView = sourceIsPrimary ? targetView : sourceView;
	Ref<Function> primaryFunction = sourceIsPrimary ? sourceFunction : targetFunction;
	Ref<Function> secondaryFunction = sourceIsPrimary ? targetFunction : sourceFunction;
	const uint64_t primaryAddress = sourceIsPrimary ? sourceInfo->address : targetInfo->address;
	const uint64_t secondaryAddress = sourceIsPrimary ? targetInfo->address : sourceInfo->address;
	security::bindiff::FlowGraph* primaryGraph = primaryView.m_callGraph.GetFlowGraph(primaryAddress);
	security::bindiff::FlowGraph* secondaryGraph = secondaryView.m_callGraph.GetFlowGraph(secondaryAddress);
	if (!primaryGraph || !secondaryGraph)
		return std::nullopt;

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
	const auto [fixedPoint, inserted] = context.AddFixedPoint(
		primaryGraph, secondaryGraph, security::bindiff::MatchingStep::kFunctionManualName);
	if (!inserted)
		return std::nullopt;
	auto* match = const_cast<security::bindiff::FixedPoint*>(&*fixedPoint);
	security::bindiff::FindFixedPointsBasicBlock(
		match, &context, security::bindiff::GetDefaultMatchingStepsBasicBlock());

	RenderAnnotations result;
	auto& primaryAnnotations = sourceIsPrimary ? result.source : result.target;
	auto& secondaryAnnotations = sourceIsPrimary ? result.target : result.source;
	for (const auto& blockMatch : match->GetBasicBlockFixedPoints())
	{
		std::unordered_set<const security::bindiff::Instruction*> primaryMatched;
		std::unordered_set<const security::bindiff::Instruction*> secondaryMatched;
		for (const auto& [primary, secondary] : blockMatch.GetInstructionMatches())
		{
			primaryMatched.insert(primary);
			secondaryMatched.insert(secondary);
		}
		AddUnmatchedInstructionAnnotations(primaryAnnotations, *primaryFunction,
			primaryGraph->GetInstructions(blockMatch.GetPrimaryVertex()), primaryMatched, SimilarityAnnotationChanged);
		AddUnmatchedInstructionAnnotations(secondaryAnnotations, *secondaryFunction,
			secondaryGraph->GetInstructions(blockMatch.GetSecondaryVertex()), secondaryMatched,
			SimilarityAnnotationChanged);
	}

	const auto& primaryBlocks = primaryGraph->GetGraph();
	for (auto [vertex, end] = boost::vertices(primaryBlocks); vertex != end; ++vertex)
	{
		if (!primaryGraph->GetFixedPoint(*vertex))
		{
			AddBlockAnnotation(primaryAnnotations, *primaryFunction, primaryGraph->GetAddress(*vertex),
				SimilarityAnnotationAdded);
		}
	}
	const auto& secondaryBlocks = secondaryGraph->GetGraph();
	for (auto [vertex, end] = boost::vertices(secondaryBlocks); vertex != end; ++vertex)
	{
		if (!secondaryGraph->GetFixedPoint(*vertex))
		{
			AddBlockAnnotation(secondaryAnnotations, *secondaryFunction, secondaryGraph->GetAddress(*vertex),
				SimilarityAnnotationRemoved);
		}
	}
	NormalizeAnnotations(result.source);
	NormalizeAnnotations(result.target);
	return result;
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
	const MatchKey key {match->first, match->second.target};
	bool sourceIsPrimary;
	std::optional<RenderAnnotations> annotations;
	{
		std::shared_lock lock(m_dataMutex);
		if (const auto entry = m_renderAnnotations.find(key); entry != m_renderAnnotations.end())
			annotations = entry->second;
		if (m_primaryMatches.contains(key))
			sourceIsPrimary = true;
		else if (m_primaryMatches.contains(MatchKey {key.secondary, key.primary}))
			sourceIsPrimary = false;
		else
			return;
	}
	if (!annotations)
	{
		annotations = BuildRenderAnnotations(
			node, match->first.entityId, *targetNode, match->second.target.entityId, sourceIsPrimary);
		if (!annotations)
			return;
		std::lock_guard lock(m_dataMutex);
		m_renderAnnotations.insert_or_assign(key, *annotations);
		m_renderAnnotations.insert_or_assign(
			MatchKey {key.secondary, key.primary}, RenderAnnotations {annotations->target, annotations->source});
	}

	const std::vector<Ref<Function>> functions {
		node.GetEntityFunction(match->first.entityId), targetNode->GetEntityFunction(match->second.target.entityId)};
	const std::array<SimilarityEntityRef, 2> entities {match->first, match->second.target};
	const std::array<const std::vector<SimilarityRangeAnnotation>*, 2> annotationSets {
		&annotations->source, &annotations->target};
	for (size_t i = 0; i < functions.size(); i++)
	{
		const auto& function = functions[i];
		if (!function)
			continue;
		Ref<DiffRenderer> renderer = new DiffRenderer();
		for (const auto& annotation : *annotationSets[i])
			renderer->AddRangeAnnotation(annotation);
		renderer->Render(context, *function, entities[i]);
	}
}
