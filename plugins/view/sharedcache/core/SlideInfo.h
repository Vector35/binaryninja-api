#pragma once

#include "binaryninjaapi.h"
#include "SharedCache.h"

// Information required to apply slide (relocation) info to a mapping
struct SlideMappingInfo
{
	dyld_cache_mapping_info mappingInfo;
	// NOTE: Offset is relative to the beginning of the entry file.
	uint64_t address;
	uint16_t slideInfoVersion;

	union
	{
		dyld_cache_slide_info_v2 slideInfoV2;
		dyld_cache_slide_info_v3 slideInfoV3;
		dyld_cache_slide_info_v5 slideInfoV5;
	};
};

// Current usages of the slide info are:
// - Reading export symbols requires slide info to be processed.
// - Reading objc stuff
// - Loading an image or region
// - Reading branch island mappings????
class SlideInfoProcessor
{
	BinaryNinja::Ref<BinaryNinja::Logger> m_logger;
	// Base address of the shared cache, NOT the base address of the entry.
	uint64_t m_baseAddress;

public:
	explicit SlideInfoProcessor(uint64_t baseAddress);

	std::vector<SlideMappingInfo> ReadEntryInfo(const MappedFileAccessor& accessor, const CacheEntry& entry) const;

	// Write the slide information back to the entries memory mapped regions.
	void ApplyMappings(MappedFileAccessor& accessor, const std::vector<SlideMappingInfo>& mappings) const;

	std::vector<SlideMappingInfo> ProcessEntry(MappedFileAccessor& accessor, const CacheEntry& entry) const;
};
