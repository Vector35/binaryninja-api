#pragma once

#include "binaryninjaapi.h"
#include "diffview.h"

#include <mutex>
#include <shared_mutex>
#include <unordered_set>

class GoogleSimilarityProviderType : public BinaryNinja::SimilarityProviderType
{
public:
	GoogleSimilarityProviderType() :
		SimilarityProviderType("Google BinDiff", "Uses Google's BinDiff project to perform binary similarity")
	{}

	BinaryNinja::Ref<BinaryNinja::SimilarityProvider> Create(BinaryNinja::Settings& settings) override;

	BinaryNinja::Ref<BinaryNinja::Settings> GetDefaultSettings() override;
};

class GoogleSimilarityProvider : public BinaryNinja::SimilarityProvider
{
	struct ViewState
	{
		std::mutex mutex;
		std::shared_ptr<BinDiffView> view;
	};

	struct MatchKey
	{
		BinaryNinja::SimilarityEntityRef primary;
		BinaryNinja::SimilarityEntityRef secondary;

		bool operator==(const MatchKey&) const = default;
	};

	struct RenderAnnotations
	{
		std::vector<BinaryNinja::SimilarityRangeAnnotation> source;
		std::vector<BinaryNinja::SimilarityRangeAnnotation> target;
	};

	struct PendingMatch
	{
		MatchKey key;
		uint8_t similarity;
		uint8_t confidence;
		std::string primaryName;
		std::string secondaryName;
	};

	struct MatchKeyHash
	{
		size_t operator()(const MatchKey& key) const
		{
			const size_t primaryHash = std::hash<BinaryNinja::SimilarityEntityRef>()(key.primary);
			const size_t secondaryHash = std::hash<BinaryNinja::SimilarityEntityRef>()(key.secondary);
			return primaryHash ^ (secondaryHash + 0x9e3779b9 + (primaryHash << 6) + (primaryHash >> 2));
		}
	};

	std::shared_mutex m_viewsMutex;
	std::unordered_map<BinaryNinja::SimilaritySessionNodeId, std::shared_ptr<ViewState>> m_views;

	std::shared_mutex m_dataMutex;
	std::unordered_map<BinaryNinja::SimilarityEntityRef, std::string> m_entityNames;
	std::unordered_set<MatchKey, MatchKeyHash> m_primaryMatches;
	std::unordered_map<MatchKey, RenderAnnotations, MatchKeyHash> m_renderAnnotations;

	std::optional<std::pair<BinaryNinja::SimilarityEntityRef, BinaryNinja::SimilarityResult>> FindResult(
		BinaryNinja::SimilaritySessionNode& node, BinaryNinja::SimilarityEntityId entity,
		BinaryNinja::SimilarityResultId result);
	static BinaryNinja::Ref<BinaryNinja::SimilaritySessionNode> FindNode(
		BinaryNinja::SimilaritySessionNode& node, BinaryNinja::SimilaritySessionNodeId id);
	std::optional<RenderAnnotations> BuildRenderAnnotations(BinaryNinja::SimilaritySessionNode& sourceNode,
		BinaryNinja::SimilarityEntityId sourceEntity, BinaryNinja::SimilaritySessionNode& targetNode,
		BinaryNinja::SimilarityEntityId targetEntity, bool sourceIsPrimary);

public:
	explicit GoogleSimilarityProvider(BinaryNinja::SimilarityProviderType* type);

	bool VisitNode(BinaryNinja::SimilaritySessionNode& node, BinaryNinja::SimilarityProviderResults& results,
		BinaryNinja::SimilaritySessionCompletion& completion) override;

	bool VisitNodeEdge(BinaryNinja::SimilaritySessionNode& from, BinaryNinja::SimilaritySessionNode& to,
		BinaryNinja::SimilarityProviderResults& results, BinaryNinja::SimilaritySessionCompletion& completion) override;

	std::optional<std::string> GetName(BinaryNinja::SimilaritySessionNode& node, BinaryNinja::SimilarityEntityId entity,
		BinaryNinja::SimilarityResultId result) override;

	void Render(BinaryNinja::SimilaritySessionNode& node, BinaryNinja::SimilarityEntityId entity,
		BinaryNinja::SimilarityRenderContext& context, BinaryNinja::SimilarityResultId result) override;
};
