#pragma once

#include "binaryninjaapi.h"

#include <mutex>

class MetricResolverType : public BinaryNinja::SimilaritySessionResolverType
{
public:
	MetricResolverType() :
		SimilaritySessionResolverType("Metric Similarity Resolver", "Uses simple metrics to resolve similarity")
	{}

	BinaryNinja::Ref<BinaryNinja::SimilaritySessionResolver> Create(
		BinaryNinja::Ref<BinaryNinja::SimilaritySession> session, BinaryNinja::Settings& settings) override;

	BinaryNinja::Ref<BinaryNinja::Settings> GetDefaultSettings() override;
};

class MetricResolver : public BinaryNinja::SimilaritySessionResolver
{
	struct Configuration
	{
		double similarityThreshold = 0.4;
		double confidenceThreshold = 0.5;
	};

	std::mutex m_configurationMutex;
	Configuration m_configuration;

public:
	MetricResolver(BinaryNinja::SimilaritySessionResolverType* type,
		BinaryNinja::Ref<BinaryNinja::SimilaritySession> session) :
		SimilaritySessionResolver(type, session)
	{}

	bool UpdateSettings(BinaryNinja::Settings& settings) override;

	void ResolveForNode(BinaryNinja::SimilaritySession& session, BinaryNinja::SimilaritySessionNode& node,
		const std::vector<BinaryNinja::SimilarityEntityId>& entities,
		BinaryNinja::SimilaritySessionCompletion& completion) override;
};
