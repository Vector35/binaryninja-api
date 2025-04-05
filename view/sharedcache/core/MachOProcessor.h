#pragma once
#include "MachO.h"

// Process `SharedCacheMachOHeader`.
class SharedCacheMachOProcessor
{
	BinaryNinja::Ref<BinaryNinja::BinaryView> m_view;
	BinaryNinja::Ref<BinaryNinja::Logger> m_logger;
	std::shared_ptr<VirtualMemory> m_vm;

	bool m_applyFunctions = true;

public:
	explicit SharedCacheMachOProcessor(
		BinaryNinja::Ref<BinaryNinja::BinaryView> view, std::shared_ptr<VirtualMemory> vm);

	// Initialize header information such as sections and symbols.
	void ApplyHeader(SharedCacheMachOHeader& header);

	uint64_t ApplyHeaderSections(SharedCacheMachOHeader& header);

	void ApplyHeaderDataVariables(SharedCacheMachOHeader& header);
};
