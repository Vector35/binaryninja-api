#include "resolver.h"

#include <cmath>
#include <map>
#include <ranges>
#include <unordered_map>
#include <unordered_set>

using namespace BinaryNinja;

namespace {
	struct Evidence
	{
		SimilarityResultId id;
		SimilarityResult result;

		uint32_t Weight() const
		{
			return static_cast<uint32_t>(result.similarity) * static_cast<uint32_t>(result.confidence);
		}

		double Confidence() const { return static_cast<double>(Weight()) / (255.0 * 255.0); }

		double Similarity() const { return static_cast<double>(result.similarity) / 255.0; }
	};

	bool IsBetterEvidence(const Evidence& candidate, const Evidence& current)
	{
		if (candidate.Weight() != current.Weight())
			return candidate.Weight() > current.Weight();
		if (candidate.result.providerId != current.result.providerId)
			return candidate.result.providerId < current.result.providerId;
		return candidate.id < current.id;
	}

	struct Candidate
	{
		std::map<SimilarityProviderId, Evidence> evidenceByProvider;

		void Add(Evidence evidence)
		{
			const SimilarityProviderId providerId = evidence.result.providerId;
			const auto existing = evidenceByProvider.find(providerId);
			if ((existing == evidenceByProvider.end()) || IsBetterEvidence(evidence, existing->second))
				evidenceByProvider.insert_or_assign(providerId, std::move(evidence));
		}

		double Confidence() const
		{
			double inverseConfidence = 1.0;
			for (const auto& evidence : evidenceByProvider | std::views::values)
				inverseConfidence *= 1.0 - evidence.Confidence();
			return 1.0 - inverseConfidence;
		}

		const Evidence& BestEvidence() const
		{
			const Evidence* best = nullptr;
			for (const auto& evidence : evidenceByProvider | std::views::values)
			{
				if (!best || IsBetterEvidence(evidence, *best))
					best = &evidence;
			}
			return *best;
		}
	};

	struct Resolution
	{
		Evidence evidence;
		double confidence;
	};

	bool IsBetterResolution(const Resolution& candidate, const Resolution& current)
	{
		if (candidate.confidence != current.confidence)
			return candidate.confidence > current.confidence;
		if (candidate.evidence.result.target != current.evidence.result.target)
			return candidate.evidence.result.target < current.evidence.result.target;
		return IsBetterEvidence(candidate.evidence, current.evidence);
	}

	void ConsiderResolution(std::optional<Resolution>& best, Resolution candidate)
	{
		if (!best || IsBetterResolution(candidate, *best))
			best = std::move(candidate);
	}
}  // namespace

Ref<SimilaritySessionResolver> MetricResolverType::Create(Ref<SimilaritySession> session, Settings& settings)
{
	Ref<MetricResolver> resolver = new MetricResolver(this, std::move(session));
	if (!resolver->UpdateSettings(settings))
		return nullptr;
	return resolver.GetPtr();
}

Ref<Settings> MetricResolverType::GetDefaultSettings()
{
	Ref<Settings> settings = Settings::Instance("metricSimilarityResolver");
	settings->RegisterGroup("metrics", "Metrics");
	settings->RegisterSetting("metrics.similarityThreshold", R"~({
			"title" : "Similarity Threshold",
			"type" : "number",
			"default" : 0.4,
			"minValue": 0.0,
			"maxValue": 1.0,
			"description" : "Ignore results below this similarity."
			})~");
	settings->RegisterSetting("metrics.confidenceThreshold", R"~({
			"title" : "Confidence Threshold",
			"type" : "number",
			"default" : 0.5,
			"minValue": 0.0,
			"maxValue": 1.0,
			"description" : "Require at least this combined confidence."
			})~");
	return settings;
}

bool MetricResolver::UpdateSettings(Settings& settings)
{
	Configuration configuration {
		.similarityThreshold = settings.Get<double>("metrics.similarityThreshold"),
		.confidenceThreshold = settings.Get<double>("metrics.confidenceThreshold"),
	};
	if (!std::isfinite(configuration.similarityThreshold) || (configuration.similarityThreshold < 0.0)
		|| (configuration.similarityThreshold > 1.0) || !std::isfinite(configuration.confidenceThreshold)
		|| (configuration.confidenceThreshold < 0.0) || (configuration.confidenceThreshold > 1.0))
		return false;
	std::lock_guard lock(m_configurationMutex);
	m_configuration = configuration;
	return true;
}

void MetricResolver::ResolveForNode(SimilaritySession& session, SimilaritySessionNode& node,
	const std::vector<SimilarityEntityId>& entities, SimilaritySessionCompletion& completion)
{
	Configuration configuration;
	{
		std::lock_guard lock(m_configurationMutex);
		configuration = m_configuration;
	}
	const Ref<SimilaritySessionGraph> graph = session.GetGraph();
	std::unordered_set<SimilaritySessionNodeId> relatedNodes {node.GetId()};
	const auto incomingNodes = node.GetIncomingEdges();
	const auto outgoingNodes = node.GetOutgoingEdges();
	relatedNodes.insert(incomingNodes.begin(), incomingNodes.end());
	relatedNodes.insert(outgoingNodes.begin(), outgoingNodes.end());

	const SimilaritySessionCompletionQuery progressQuery {node.GetId(), std::nullopt, GetId()};
	if (entities.empty())
		completion.SetProgress(progressQuery, 0.99);
	for (size_t entityIndex = 0; entityIndex < entities.size(); entityIndex++)
	{
		if (completion.IsStopRequested())
			return;
		const auto sourceEntity = entities[entityIndex];
		std::unordered_map<SimilarityEntityRef, Candidate> candidates;
		std::optional<Resolution> best;
		for (const auto resultId : node.GetResults(sourceEntity))
		{
			if (completion.IsStopRequested())
				return;
			const auto result = node.GetResult(resultId);
			if (!result)
				continue;
			Evidence evidence {resultId, *result};
			if (evidence.Similarity() < configuration.similarityThreshold)
				continue;
			if ((result->target.nodeId == node.GetId()) && (result->target.entityId == sourceEntity))
				continue;
			if (!relatedNodes.contains(result->target.nodeId))
				continue;

			const Ref<SimilaritySessionNode> targetNode = graph->GetNode(result->target.nodeId);
			if (!targetNode || !targetNode->GetEntity(result->target.entityId))
				continue;
			candidates[result->target].Add(std::move(evidence));
		}

		for (const auto& candidate : candidates | std::views::values)
		{
			if (completion.IsStopRequested())
				return;
			ConsiderResolution(best, {candidate.BestEvidence(), candidate.Confidence()});
		}

		if (best && (best->confidence >= configuration.confidenceThreshold))
			node.SetResolvedResult(sourceEntity, best->evidence.id);
		else
			node.ClearResolvedResult(sourceEntity);
		completion.SetProgress(progressQuery, 0.99 * (static_cast<double>(entityIndex + 1) / entities.size()));
	}
}
