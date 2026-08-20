#include "SlideInfo.h"

#include "Dyld.h"
#include "SharedCache.h"
#include "Utility.h"

SlideInfoProcessor::SlideInfoProcessor(uint64_t baseAddress)
{
	m_logger = new BinaryNinja::Logger("SlideInfo.Processor");
	m_baseAddress = baseAddress;
}

void ApplySlideInfoV5(MappedFileRegion& file, const SlideMappingInfo& mapping)
{
	uint64_t pageStartsOffset = mapping.address + sizeof(dyld_cache_slide_info_v5);
	uint64_t pageStartCount = mapping.slideInfoV5.page_starts_count;
	uint64_t pageSize = mapping.slideInfoV5.page_size;

	auto cursor = pageStartsOffset;
	for (size_t i = 0; i < pageStartCount; i++)
	{
		uint16_t delta = file.ReadUInt16(cursor);
		cursor += sizeof(uint16_t);
		if (delta == DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE)
			continue;

		delta = delta / sizeof(uint64_t);  // initial offset is byte based
		uint64_t loc = mapping.mappingInfo.fileOffset + (pageSize * i);
		do
		{
			loc += delta * sizeof(dyld_cache_slide_pointer5);
			dyld_cache_slide_pointer5 slideInfo = {file.ReadUInt64(loc)};
			delta = slideInfo.regular.next;
			if (slideInfo.auth.auth)
			{
				uint64_t value = mapping.slideInfoV5.value_add + slideInfo.auth.runtimeOffset;
				file.WriteUInt64(loc, value);
			}
			else
			{
				uint64_t value = mapping.slideInfoV5.value_add + slideInfo.regular.runtimeOffset;
				file.WriteUInt64(loc, value);
			}
		} while (delta != 0);
	}
}

void ApplySlideInfoV3(MappedFileRegion& file, const SlideMappingInfo& mapping)
{
	uint64_t pageStartsOffset = mapping.address + sizeof(dyld_cache_slide_info_v3);
	uint64_t pageStartCount = mapping.slideInfoV3.page_starts_count;
	uint64_t pageSize = mapping.slideInfoV3.page_size;

	auto cursor = pageStartsOffset;
	for (size_t i = 0; i < pageStartCount; i++)
	{
		uint16_t delta = file.ReadUInt16(cursor);
		cursor += sizeof(uint16_t);
		if (delta == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE)
			continue;

		delta = delta / sizeof(uint64_t);  // initial offset is byte based
		uint64_t loc = mapping.mappingInfo.fileOffset + (pageSize * i);
		do
		{
			loc += delta * sizeof(dyld_cache_slide_pointer3);
			dyld_cache_slide_pointer3 slideInfo = {file.ReadUInt64(loc)};
			delta = slideInfo.plain.offsetToNextPointer;

			if (slideInfo.auth.authenticated)
			{
				uint64_t value = slideInfo.auth.offsetFromSharedCacheBase;
				value += mapping.slideInfoV3.auth_value_add;
				file.WriteUInt64(loc, value);
			}
			else
			{
				uint64_t value51 = slideInfo.plain.pointerValue;
				uint64_t top8Bits = value51 & 0x0007F80000000000;
				uint64_t bottom43Bits = value51 & 0x000007FFFFFFFFFF;
				uint64_t value = (uint64_t)top8Bits << 13 | bottom43Bits;
				file.WriteUInt64(loc, value);
			}
		} while (delta != 0);
	}
}

void ApplySlideInfoV2(MappedFileRegion& file, const SlideMappingInfo& mapping)
{
	auto rebaseChain = [&](const dyld_cache_slide_info_v2& slideInfo, uint64_t pageContent, uint16_t startOffset) {
		// TODO: This is always zero?
		// TODO: This is probably something for runtime offsets provided to the shared cache.
		uintptr_t slideAmount = 0;

		auto deltaMask = slideInfo.delta_mask;
		auto valueMask = ~deltaMask;
		auto valueAdd = slideInfo.value_add;

		auto deltaShift = CountTrailingZeros(deltaMask) - 2;

		uint32_t pageOffset = startOffset;
		uint32_t delta = 1;
		while (delta != 0)
		{
			uint64_t loc = pageContent + pageOffset;
			uintptr_t rawValue = file.ReadUInt64(loc);
			delta = (uint32_t)((rawValue & deltaMask) >> deltaShift);
			uintptr_t value = (rawValue & valueMask);
			if (value != 0)
			{
				value += valueAdd;
				// TODO: slideAmount += value?
				// TODO: slideAmount is always zero? What is this suppose to do?
				value += slideAmount;
			}
			pageOffset += delta;
			file.WriteUInt64(loc, value);
		}
	};

	uint64_t extrasOffset = mapping.address + mapping.slideInfoV2.page_extras_offset;
	uint64_t pageStartsOffset = mapping.address + sizeof(dyld_cache_slide_info_v2);
	uint64_t pageStartCount = mapping.slideInfoV2.page_starts_count;
	uint64_t pageSize = mapping.slideInfoV2.page_size;

	auto cursor = pageStartsOffset;
	for (size_t i = 0; i < pageStartCount; i++)
	{
		uint16_t start = file.ReadUInt16(cursor);
		cursor += sizeof(uint16_t);
		if (start == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE)
			continue;

		if (start & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA)
		{
			int j = (start & 0x3FFF);
			bool done = false;
			do
			{
				uint64_t extraCursor = extrasOffset + (j * sizeof(uint16_t));
				auto extra = file.ReadUInt16(extraCursor);
				uint16_t aStart = extra;
				uint64_t page = mapping.mappingInfo.fileOffset + (pageSize * i);
				uint16_t pageStartOffset = (aStart & 0x3FFF) * 4;
				rebaseChain(mapping.slideInfoV2, page, pageStartOffset);
				done = (extra & DYLD_CACHE_SLIDE_PAGE_ATTR_END);
				++j;
			} while (!done);
		}
		else
		{
			uint64_t page = mapping.mappingInfo.fileOffset + (pageSize * i);
			uint16_t pageStartOffset = start * 4;
			rebaseChain(mapping.slideInfoV2, page, pageStartOffset);
		}
	}
}

std::vector<SlideMappingInfo> SlideInfoProcessor::ReadEntryInfo(const MappedFileRegion& file, const CacheEntry& entry) const
{
	const auto& baseHeader = entry.GetHeader();

	// Handle legacy, single mapping slide info.
	if (baseHeader.slideInfoOffsetUnused)
	{
		auto slideInfoAddress = baseHeader.slideInfoOffsetUnused;
		auto slideInfoVersion = file.ReadUInt32(slideInfoAddress);
		if (slideInfoVersion != 2 && slideInfoVersion != 3)
		{
			m_logger->LogErrorF("Unsupported slide info version {}", slideInfoVersion);
			return {};
		}

		SlideMappingInfo singleMapping = {};
		singleMapping.address = slideInfoAddress;
		singleMapping.slideInfoVersion = slideInfoVersion;

		auto mappingAddress = baseHeader.mappingOffset + sizeof(dyld_cache_mapping_info);
		file.Read(&singleMapping.mappingInfo, mappingAddress, sizeof(dyld_cache_mapping_info));
		if (singleMapping.slideInfoVersion == 2)
			file.Read(&singleMapping.slideInfoV2, slideInfoAddress, sizeof(dyld_cache_slide_info_v2));
		else if (singleMapping.slideInfoVersion == 3)
			file.Read(&singleMapping.slideInfoV3, slideInfoAddress, sizeof(dyld_cache_slide_info_v3));

		return {singleMapping};
	}

	std::vector<SlideMappingInfo> mappings = {};
	for (auto i = 0; i < baseHeader.mappingWithSlideCount; i++)
	{
		dyld_cache_mapping_and_slide_info mappingAndSlideInfo = {};
		auto mappingAndSlideInfoAddress = baseHeader.mappingWithSlideOffset + (i * sizeof(dyld_cache_mapping_and_slide_info));
		file.Read(&mappingAndSlideInfo, mappingAndSlideInfoAddress, sizeof(dyld_cache_mapping_and_slide_info));
		if (mappingAndSlideInfo.size == 0 || mappingAndSlideInfo.slideInfoFileOffset == 0)
			continue;

		SlideMappingInfo map = {};
		map.address = mappingAndSlideInfo.slideInfoFileOffset;
		map.slideInfoVersion = file.ReadUInt32(map.address);
		map.mappingInfo.address = mappingAndSlideInfo.address;
		map.mappingInfo.size = mappingAndSlideInfo.size;
		map.mappingInfo.fileOffset = mappingAndSlideInfo.fileOffset;
		if (map.slideInfoVersion == 2)
		{
			file.Read(&map.slideInfoV2, map.address, sizeof(dyld_cache_slide_info_v2));
		}
		else if (map.slideInfoVersion == 3)
		{
			file.Read(&map.slideInfoV3, map.address, sizeof(dyld_cache_slide_info_v3));
			map.slideInfoV3.auth_value_add = m_baseAddress;
		}
		else if (map.slideInfoVersion == 5)
		{
			file.Read(&map.slideInfoV5, map.address, sizeof(dyld_cache_slide_info_v5));
			map.slideInfoV5.value_add = m_baseAddress;
		}
		else
		{
			m_logger->LogErrorF("Unknown slide info version: {}", map.slideInfoVersion);
			continue;
		}

		mappings.emplace_back(map);
		m_logger->LogDebugF("File: {:?}", entry.GetFilePath().c_str());
		m_logger->LogDebugF("Slide Info Address: {:#x}", map.address);
		uint64_t mappingAddress = map.mappingInfo.address;
		m_logger->LogDebugF("Mapping Address: {:#x}", mappingAddress);
		m_logger->LogDebugF("Slide Info Version: {}", map.slideInfoVersion);
	}

	return mappings;
}

void SlideInfoProcessor::ApplyMappings(MappedFileRegion& file, const std::vector<SlideMappingInfo>& mappings) const
{
	// Apply the slide information to the mapped file.
	for (const auto& mapping : mappings)
	{
		switch (mapping.slideInfoVersion)
		{
		case 2:
			ApplySlideInfoV2(file, mapping);
			break;
		case 3:
			ApplySlideInfoV3(file, mapping);
			break;
		case 5:
			ApplySlideInfoV5(file, mapping);
			break;
		default:
			m_logger->LogErrorF(
				"Cannot apply slide info version: {} @ {:#x}", mapping.slideInfoVersion, mapping.mappingInfo.address);
			break;
		}
	}
}

std::vector<SlideMappingInfo> SlideInfoProcessor::ProcessEntry(MappedFileRegion& file, const CacheEntry& entry) const
{
	try
	{
		auto slideMappings = ReadEntryInfo(file, entry);
		ApplyMappings(file, slideMappings);
		return slideMappings;
	}
	catch (const std::exception& e)
	{
		// Just log an error, we technically can continue as if the slide info is not applied for a given entry it does
		// not necessarily mean we cannot do analysis on others.
		m_logger->LogErrorF("Error processing slide info for entry {:?}: {}", entry.GetFileName().c_str(), e.what());
		return {};
	}
}
