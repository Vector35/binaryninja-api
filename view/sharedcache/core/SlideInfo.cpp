#include "SlideInfo.h"

#include "Dyld.h"
#include "SharedCache.h"
#include "Utility.h"

SlideInfoProcessor::SlideInfoProcessor(uint64_t baseAddress)
{
	m_logger = new BinaryNinja::Logger("SlideInfoProcessor");
	m_baseAddress = baseAddress;
}

void ApplySlideInfoV5(VirtualMemory& vm, const SlideMappingInfo& mapping)
{
	uint64_t pageStartsOffset = mapping.address + sizeof(dyld_cache_slide_info_v5);
	uint64_t pageStartCount = mapping.slideInfoV5.page_starts_count;
	uint64_t pageSize = mapping.slideInfoV5.page_size;

	auto cursor = pageStartsOffset;
	for (size_t i = 0; i < pageStartCount; i++)
	{
		uint16_t delta = vm.ReadUInt16(cursor);
		cursor += sizeof(uint16_t);
		if (delta == DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE)
			continue;

		delta = delta / sizeof(uint64_t);  // initial offset is byte based
		uint64_t loc = mapping.mappingInfo.fileOffset + (pageSize * i);
		do
		{
			loc += delta * sizeof(dyld_cache_slide_pointer5);
			dyld_cache_slide_pointer5 slideInfo = {vm.ReadUInt64(loc)};
			delta = slideInfo.regular.next;
			if (slideInfo.auth.auth)
			{
				uint64_t value = mapping.slideInfoV5.value_add + slideInfo.auth.runtimeOffset;
				vm.WritePointer(loc, value);
			}
			else
			{
				uint64_t value = mapping.slideInfoV5.value_add + slideInfo.regular.runtimeOffset;
				vm.WritePointer(loc, value);
			}
		} while (delta != 0);
	}
}

void ApplySlideInfoV3(VirtualMemory& vm, const SlideMappingInfo& mapping)
{
	uint64_t pageStartsOffset = mapping.address + sizeof(dyld_cache_slide_info_v3);
	uint64_t pageStartCount = mapping.slideInfoV3.page_starts_count;
	uint64_t pageSize = mapping.slideInfoV3.page_size;

	auto cursor = pageStartsOffset;
	for (size_t i = 0; i < pageStartCount; i++)
	{
		uint16_t delta = vm.ReadUInt16(cursor);
		cursor += sizeof(uint16_t);
		if (delta == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE)
			continue;

		delta = delta / sizeof(uint64_t);  // initial offset is byte based
		uint64_t loc = mapping.mappingInfo.fileOffset + (pageSize * i);
		do
		{
			loc += delta * sizeof(dyld_cache_slide_pointer3);
			dyld_cache_slide_pointer3 slideInfo = {vm.ReadUInt64(loc)};
			delta = slideInfo.plain.offsetToNextPointer;

			if (slideInfo.auth.authenticated)
			{
				uint64_t value = slideInfo.auth.offsetFromSharedCacheBase;
				value += mapping.slideInfoV3.auth_value_add;
				vm.WritePointer(loc, value);
			}
			else
			{
				uint64_t value51 = slideInfo.plain.pointerValue;
				uint64_t top8Bits = value51 & 0x0007F80000000000;
				uint64_t bottom43Bits = value51 & 0x000007FFFFFFFFFF;
				uint64_t value = (uint64_t)top8Bits << 13 | bottom43Bits;
				vm.WritePointer(loc, value);
			}
		} while (delta != 0);
	}
}

void ApplySlideInfoV2(VirtualMemory& vm, const SlideMappingInfo& mapping)
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
			uintptr_t rawValue = vm.ReadUInt64(loc);
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
			vm.WritePointer(loc, value);
		}
	};

	uint64_t extrasOffset = mapping.address + mapping.slideInfoV2.page_extras_offset;
	uint64_t pageStartsOffset = mapping.address + sizeof(dyld_cache_slide_info_v2);
	uint64_t pageStartCount = mapping.slideInfoV2.page_starts_count;
	uint64_t pageSize = mapping.slideInfoV2.page_size;

	auto cursor = pageStartsOffset;
	for (size_t i = 0; i < pageStartCount; i++)
	{
		uint16_t start = vm.ReadUInt16(cursor);
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
				auto extra = vm.ReadUInt16(extraCursor);
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

std::vector<SlideMappingInfo> SlideInfoProcessor::ReadEntryInfo(VirtualMemory& vm, const CacheEntry& entry) const
{
	auto& baseHeader = entry.GetHeader();

	// Handle legacy, single mapping slide info.
	if (baseHeader.slideInfoOffsetUnused)
	{
		auto slideInfoAddress = entry.GetMappedAddress(baseHeader.slideInfoOffsetUnused);
		if (!slideInfoAddress.has_value())
		{
			m_logger->LogError("Unmapped slide info address %llx", slideInfoAddress);
			return {};
		}
		auto slideInfoVersion = vm.ReadUInt32(*slideInfoAddress);
		if (slideInfoVersion != 2 && slideInfoVersion != 3)
		{
			m_logger->LogError("Unsupported slide info version %d", slideInfoVersion);
			return {};
		}

		SlideMappingInfo singleMapping = {};
		singleMapping.address = *slideInfoAddress;

		auto mappingAddress = entry.GetMappedAddress(baseHeader.mappingOffset + sizeof(dyld_cache_mapping_info));
		if (!mappingAddress.has_value())
		{
			m_logger->LogError("Unmapped mapping address %llx", mappingAddress);
			return {};
		}
		vm.Read(&singleMapping.mappingInfo, *mappingAddress, sizeof(dyld_cache_mapping_info));
		singleMapping.slideInfoVersion = slideInfoVersion;
		if (singleMapping.slideInfoVersion == 2)
			vm.Read(&singleMapping.slideInfoV2, *slideInfoAddress, sizeof(dyld_cache_slide_info_v2));
		else if (singleMapping.slideInfoVersion == 3)
			vm.Read(&singleMapping.slideInfoV3, *slideInfoAddress, sizeof(dyld_cache_slide_info_v3));

		// Adjust the file offset to mapped, we are expecting the consumer to just take it in as mapped.
		// if we did not make it mapped, then we would need to do all this weirdness in every consumer (each slide info version)
		singleMapping.mappingInfo.fileOffset = *entry.GetMappedAddress(singleMapping.mappingInfo.fileOffset);

		return {singleMapping};
	}

	std::vector<SlideMappingInfo> mappings = {};
	for (auto i = 0; i < baseHeader.mappingWithSlideCount; i++)
	{
		dyld_cache_mapping_and_slide_info mappingAndSlideInfo = {};
		auto mappingAndSlideInfoAddress =
			entry.GetMappedAddress(baseHeader.mappingWithSlideOffset + (i * sizeof(dyld_cache_mapping_and_slide_info)));
		if (!mappingAndSlideInfoAddress.has_value())
		{
			m_logger->LogError("Unmapped mapping and slide info address %llx", mappingAndSlideInfoAddress);
			continue;
		}

		vm.Read(&mappingAndSlideInfo, *mappingAndSlideInfoAddress, sizeof(dyld_cache_mapping_and_slide_info));
		if (mappingAndSlideInfo.size == 0 || mappingAndSlideInfo.slideInfoFileOffset == 0)
			continue;

		SlideMappingInfo map = {};
		map.address = *entry.GetMappedAddress(mappingAndSlideInfo.slideInfoFileOffset);
		map.slideInfoVersion = vm.ReadUInt32(map.address);
		map.mappingInfo.address = mappingAndSlideInfo.address;
		map.mappingInfo.size = mappingAndSlideInfo.size;
		map.mappingInfo.fileOffset = *entry.GetMappedAddress(mappingAndSlideInfo.fileOffset);
		if (map.slideInfoVersion == 2)
		{
			vm.Read(&map.slideInfoV2, map.address, sizeof(dyld_cache_slide_info_v2));
		}
		else if (map.slideInfoVersion == 3)
		{
			vm.Read(&map.slideInfoV3, map.address, sizeof(dyld_cache_slide_info_v3));
			map.slideInfoV3.auth_value_add = m_baseAddress;
		}
		else if (map.slideInfoVersion == 5)
		{
			vm.Read(&map.slideInfoV5, map.address, sizeof(dyld_cache_slide_info_v5));
			map.slideInfoV5.value_add = m_baseAddress;
		}
		else
		{
			m_logger->LogError("Unknown slide info version: %d", map.slideInfoVersion);
			continue;
		}

		mappings.emplace_back(map);
		m_logger->LogDebug("File: %s", entry.GetFilePath().c_str());
		m_logger->LogDebug("Slide Info Address: 0x%llx", map.address);
		m_logger->LogDebug("Mapping Address: 0x%llx", map.mappingInfo.address);
		m_logger->LogDebug("Slide Info Version: %d", map.slideInfoVersion);
	}

	return mappings;
}

void SlideInfoProcessor::ApplyMappings(VirtualMemory& vm, const std::vector<SlideMappingInfo>& mappings)
{
	// Apply the slide information to the mapped file.
	for (const auto& mapping : mappings)
	{
		switch (mapping.slideInfoVersion)
		{
		case 2:
			ApplySlideInfoV2(vm, mapping);
			break;
		case 3:
			ApplySlideInfoV3(vm, mapping);
			break;
		case 5:
			ApplySlideInfoV5(vm, mapping);
			break;
		default:
			m_logger->LogError(
				"Cannot apply slide info version: %d @ %llx", mapping.slideInfoVersion, mapping.mappingInfo.address);
			break;
		}
	}
}

void SlideInfoProcessor::ProcessEntry(VirtualMemory& vm, const CacheEntry& entry)
{
	try
	{
		ApplyMappings(vm, ReadEntryInfo(vm, entry));
	}
	catch (const std::exception& e)
	{
		// Just log an error, we technically can continue as if the slide info is not applied for a given entry it does
		// not necessarily mean we cannot do analysis on others.
		m_logger->LogError("Error processing slide info for entry `%s`: %s", entry.GetFileName().c_str(), e.what());
	}
}
