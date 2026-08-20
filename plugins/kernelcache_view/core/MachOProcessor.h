#pragma once
#include "MachO.h"
#include "KernelCache.h"

// Process `KernelCacheMachOHeader`.
class KernelCacheMachOProcessor
{
	BinaryNinja::Ref<BinaryNinja::BinaryView> m_view;
	BinaryNinja::Ref<BinaryNinja::Logger> m_logger;

	bool m_applyFunctions = true;

public:
	explicit KernelCacheMachOProcessor(BinaryNinja::Ref<BinaryNinja::BinaryView> view);

	// Initialize header information such as sections and symbols.
	void ApplyHeader(const KernelCache& cache, KernelCacheMachOHeader& header);

	uint64_t ApplyHeaderSections(KernelCacheMachOHeader& header);

	void ApplyHeaderDataVariables(KernelCacheMachOHeader& header);
};
