#pragma once

#include "binaryninjaapi.h"
#include "KernelCache.h"

// This constructs a Cache
class KernelCacheBuilder
{
	BinaryNinja::Ref<BinaryNinja::BinaryView> m_view;
	BinaryNinja::Ref<BinaryNinja::Logger> m_logger;
	// This cache is what is returned via `Finalize`.
	KernelCache m_cache;

public:
	explicit KernelCacheBuilder(BinaryNinja::Ref<BinaryNinja::BinaryView> view);

	KernelCache& GetCache() { return m_cache; };
	// Returns a shared cache that is ready for processing, this should include all the required shared cache entries.
	KernelCache Finalize();
};
