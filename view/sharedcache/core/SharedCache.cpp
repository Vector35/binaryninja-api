//
// Created by kat on 5/19/23.
//

#include "binaryninjaapi.h"

/* ---
 * This is the primary image loader logic for Shared Caches
 *
 * It is standalone code that operates on a DSCView.
 *
 * This has to recreate _all_ of the Mach-O View logic, but slightly differently, as everything is spicy and weird and
 * 		different enough that it's not worth trying to make a shared base class.
 *
 * The SharedCache api object is a 'Controller' that serializes its own state in view metadata.
 *
 * It is multithreading capable (multiple SharedCache objects can exist and do things on different threads, it will manage)
 *
 * View state is saved to BinaryView any time it changes, however due to json deser speed we must also cache it on heap.
 *	This cache is 'load bearing' and controllers on other threads may serialize it back to view after making changes, so it
 *	must be kept up to date.
 *
 *
 *
 * */

#include "SharedCache.h"
#include "ObjC.h"
#include <filesystem>
#include <utility>
#include <fcntl.h>
#include <memory>
#include <chrono>
#include <thread>


using namespace BinaryNinja;
using namespace SharedCacheCore;

#ifdef _MSC_VER

int count_trailing_zeros(uint64_t value) {
	unsigned long index; // 32-bit long on Windows
	if (_BitScanForward64(&index, value)) {
		return index;
	} else {
		return 64; // If the value is 0, return 64.
	}
}
#else
int count_trailing_zeros(uint64_t value) {
	return value == 0 ? 64 : __builtin_ctzll(value);
}
#endif

struct ViewStateCacheStore {
	SharedCache::SharedCacheFormat m_cacheFormat;

	DSCViewState m_viewState;

	std::unordered_map<std::string, uint64_t> m_imageStarts;
	std::unordered_map<uint64_t, SharedCacheMachOHeader> m_headers;

	std::vector<CacheImage> m_images;
	std::vector<MemoryRegion> m_regionsMappedIntoMemory;

	std::vector<BackingCache> m_backingCaches;
	std::vector<MemoryRegion> m_stubIslandRegions; // TODO honestly both of these should be refactored into nonImageRegions. :p
	std::vector<MemoryRegion> m_dyldDataRegions;
	std::vector<MemoryRegion> m_nonImageRegions;

	std::string m_baseFilePath;

	std::unordered_map<uint64_t, std::vector<std::pair<uint64_t, std::pair<BNSymbolType, std::string>>>> m_exportInfos;
	std::unordered_map<uint64_t, std::vector<std::pair<uint64_t, std::pair<BNSymbolType, std::string>>>> m_symbolInfos;
};

static std::recursive_mutex viewStateMutex;
static std::unordered_map<uint64_t, ViewStateCacheStore> viewStateCache;

std::mutex progressMutex;
std::unordered_map<uint64_t, BNDSCViewLoadProgress> progressMap;

struct ViewSpecificMutexes {
	std::mutex viewOperationsThatInfluenceMetadataMutex;
	std::mutex typeLibraryLookupAndApplicationMutex;
};

static std::unordered_map<uint64_t, ViewSpecificMutexes> viewSpecificMutexes;


std::string base_name(std::string const& path)
{
	return path.substr(path.find_last_of("/\\") + 1);
}


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
static int64_t readSLEB128(DataBuffer& buffer, size_t length, size_t& offset)
{
	uint8_t cur;
	int64_t value = 0;
	size_t shift = 0;
	while (offset < length)
	{
		cur = buffer[offset++];
		value |= (cur & 0x7f) << shift;
		shift += 7;
		if ((cur & 0x80) == 0)
			break;
	}
	value = (value << (64 - shift)) >> (64 - shift);
	return value;
}
#pragma clang diagnostic pop


static uint64_t readLEB128(DataBuffer& p, size_t end, size_t& offset)
{
	uint64_t result = 0;
	int bit = 0;
	do
	{
		if (offset >= end)
			return -1;

		uint64_t slice = p[offset] & 0x7f;

		if (bit > 63)
			return -1;
		else
		{
			result |= (slice << bit);
			bit += 7;
		}
	} while (p[offset++] & 0x80);
	return result;
}


uint64_t readValidULEB128(DataBuffer& buffer, size_t& cursor)
{
	uint64_t value = readLEB128(buffer, buffer.GetLength(), cursor);
	if ((int64_t)value == -1)
		throw ReadException();
	return value;
}


uint64_t SharedCache::FastGetBackingCacheCount(BinaryNinja::Ref<BinaryNinja::BinaryView> dscView)
{
	std::shared_ptr<MMappedFileAccessor> baseFile;
	try {
		baseFile = MMappedFileAccessor::Open(dscView, dscView->GetFile()->GetSessionId(), dscView->GetFile()->GetOriginalFilename())->lock();
	}
	catch (...){
		LogError("Shared Cache preload: Failed to open file %s", dscView->GetFile()->GetOriginalFilename().c_str());
		return 0;
	}

	dyld_cache_header header {};
	size_t header_size = baseFile->ReadUInt32(16);
	baseFile->Read(&header, 0, std::min(header_size, sizeof(dyld_cache_header)));

	SharedCacheFormat cacheFormat;

	if (header.imagesCountOld != 0)
		cacheFormat = RegularCacheFormat;

	size_t subCacheOff = offsetof(struct dyld_cache_header, subCacheArrayOffset);
	size_t headerEnd = header.mappingOffset;
	if (headerEnd > subCacheOff)
	{
		if (header.cacheType != 2)
		{
			if (std::filesystem::exists(ResolveFilePath(dscView, baseFile->Path() + ".01")))
				cacheFormat = LargeCacheFormat;
			else
				cacheFormat = SplitCacheFormat;
		}
		else
			cacheFormat = iOS16CacheFormat;
	}

	switch (cacheFormat)
	{
	case RegularCacheFormat:
	{
		return 1;
	}
	case LargeCacheFormat:
	{
		auto mainFileName = baseFile->Path();
		auto subCacheCount = header.subCacheArrayCount;
		return subCacheCount + 1;
	}
	case SplitCacheFormat:
	{
		auto mainFileName = baseFile->Path();
		auto subCacheCount = header.subCacheArrayCount;
		return subCacheCount + 2;
	}
	case iOS16CacheFormat:
	{
		auto mainFileName = baseFile->Path();
		auto subCacheCount = header.subCacheArrayCount;
		return subCacheCount + 2;
	}
	}
}


void SharedCache::PerformInitialLoad()
{
	m_logger->LogInfo("Performing initial load of Shared Cache");
	auto path = m_dscView->GetFile()->GetOriginalFilename();
	auto baseFile = MMappedFileAccessor::Open(m_dscView, m_dscView->GetFile()->GetSessionId(), path)->lock();

    progressMutex.lock();
	progressMap[m_dscView->GetFile()->GetSessionId()] = LoadProgressLoadingCaches;
	progressMutex.unlock();

	m_baseFilePath = path;

	DataBuffer sig = baseFile->ReadBuffer(0, 4);
	if (sig.GetLength() != 4)
		abort();
	const char* magic = (char*)sig.GetData();
	if (strncmp(magic, "dyld", 4) != 0)
		abort();

	m_cacheFormat = RegularCacheFormat;

	dyld_cache_header primaryCacheHeader {};
	size_t header_size = baseFile->ReadUInt32(16);
	baseFile->Read(&primaryCacheHeader, 0, std::min(header_size, sizeof(dyld_cache_header)));

	if (primaryCacheHeader.imagesCountOld != 0)
		m_cacheFormat = RegularCacheFormat;

	size_t subCacheOff = offsetof(struct dyld_cache_header, subCacheArrayOffset);
	size_t headerEnd = primaryCacheHeader.mappingOffset;
	if (headerEnd > subCacheOff)
	{
		if (primaryCacheHeader.cacheType != 2)
		{
			if (std::filesystem::exists(ResolveFilePath(m_dscView, baseFile->Path() + ".01")))
				m_cacheFormat = LargeCacheFormat;
			else
				m_cacheFormat = SplitCacheFormat;
		}
		else
			m_cacheFormat = iOS16CacheFormat;
	}

	switch (m_cacheFormat)
	{
	case RegularCacheFormat:
	{
		dyld_cache_mapping_info mapping {};
		BackingCache cache;
		cache.isPrimary = true;
		cache.path = path;

		for (size_t i = 0; i < primaryCacheHeader.mappingCount; i++)
		{
			baseFile->Read(&mapping, primaryCacheHeader.mappingOffset + (i * sizeof(mapping)), sizeof(mapping));
			std::pair<uint64_t, std::pair<uint64_t, uint64_t>> mapRawToAddrAndSize;
			mapRawToAddrAndSize.first = mapping.fileOffset;
			mapRawToAddrAndSize.second.first = mapping.address;
			mapRawToAddrAndSize.second.second = mapping.size;
			cache.mappings.push_back(mapRawToAddrAndSize);
		}
		m_backingCaches.push_back(cache);

		dyld_cache_image_info img {};

		for (size_t i = 0; i < primaryCacheHeader.imagesCountOld; i++)
		{
			baseFile->Read(&img, primaryCacheHeader.imagesOffsetOld + (i * sizeof(img)), sizeof(img));
			auto iname = baseFile->ReadNullTermString(img.pathFileOffset);
			m_imageStarts[iname] = img.address;
		}

		m_logger->LogInfo("Found %d images in the shared cache", primaryCacheHeader.imagesCountOld);

		if (primaryCacheHeader.branchPoolsCount)
		{
			std::vector<uint64_t> addresses;
			for (size_t i = 0; i < primaryCacheHeader.branchPoolsCount; i++)
			{
				addresses.push_back(baseFile->ReadULong(primaryCacheHeader.branchPoolsOffset + (i * m_dscView->GetAddressSize())));
			}
			baseFile.reset(); // No longer needed, we're about to remap this file into VM space so we can load these.
			uint64_t i = 0;
			for (auto address : addresses)
			{
				i++;
				auto vm = GetVMMap(true);
				auto machoHeader = SharedCache::LoadHeaderForAddress(vm, address, "dyld_shared_cache_branch_islands_" + std::to_string(i));
				if (machoHeader)
				{
					for (const auto& segment : machoHeader->segments)
					{
						MemoryRegion stubIslandRegion;
						stubIslandRegion.start = segment.vmaddr;
						stubIslandRegion.size = segment.filesize;
						char segName[17];
						memcpy(segName, segment.segname, 16);
						segName[16] = 0;
						std::string segNameStr = std::string(segName);
						stubIslandRegion.prettyName = "dyld_shared_cache_branch_islands_" + std::to_string(i) + "::" + segNameStr;
						stubIslandRegion.flags = (BNSegmentFlag)(BNSegmentFlag::SegmentReadable | BNSegmentFlag::SegmentExecutable);
						m_stubIslandRegions.push_back(stubIslandRegion);
					}
				}
			}
		}

		m_logger->LogInfo("Found %d branch pools in the shared cache", primaryCacheHeader.branchPoolsCount);

		break;
	}
	case LargeCacheFormat:
	{
		dyld_cache_mapping_info mapping {};	 // We're going to reuse this for all of the mappings. We only need it
											 // briefly.

		BackingCache cache;
		cache.isPrimary = true;
		cache.path = path;

		for (size_t i = 0; i < primaryCacheHeader.mappingCount; i++)
		{
			baseFile->Read(&mapping, primaryCacheHeader.mappingOffset + (i * sizeof(mapping)), sizeof(mapping));
			std::pair<uint64_t, std::pair<uint64_t, uint64_t>> mapRawToAddrAndSize;
			mapRawToAddrAndSize.first = mapping.fileOffset;
			mapRawToAddrAndSize.second.first = mapping.address;
			mapRawToAddrAndSize.second.second = mapping.size;
			cache.mappings.push_back(mapRawToAddrAndSize);
		}
		m_backingCaches.push_back(cache);

		dyld_cache_image_info img {};

		for (size_t i = 0; i < primaryCacheHeader.imagesCount; i++)
		{
			baseFile->Read(&img, primaryCacheHeader.imagesOffset + (i * sizeof(img)), sizeof(img));
			auto iname = baseFile->ReadNullTermString(img.pathFileOffset);
			m_imageStarts[iname] = img.address;
		}

		if (primaryCacheHeader.branchPoolsCount)
		{
			std::vector<uint64_t> pool {};
			for (size_t i = 0; i < primaryCacheHeader.branchPoolsCount; i++)
			{
				m_imageStarts["dyld_shared_cache_branch_islands_" + std::to_string(i)] = baseFile->ReadULong(primaryCacheHeader.branchPoolsOffset + (i * m_dscView->GetAddressSize()));
			}
		}
		std::string mainFileName = base_name(path);
		if (auto projectFile = m_dscView->GetFile()->GetProjectFile())
			mainFileName = projectFile->GetName();
		auto subCacheCount = primaryCacheHeader.subCacheArrayCount;

		dyld_subcache_entry2 _entry {};
		std::vector<dyld_subcache_entry2> subCacheEntries;
		for (size_t i = 0; i < subCacheCount; i++)
		{
			baseFile->Read(&_entry, primaryCacheHeader.subCacheArrayOffset + (i * sizeof(dyld_subcache_entry2)),
				sizeof(dyld_subcache_entry2));
			subCacheEntries.push_back(_entry);
		}

		baseFile.reset();
		for (const auto& entry : subCacheEntries)
		{
			std::string subCachePath;
			std::string subCacheFilename;
			if (std::string(entry.fileExtension).find('.') != std::string::npos)
			{
				subCachePath = path + entry.fileExtension;
				subCacheFilename = mainFileName + entry.fileExtension;
			}
			else
			{
				subCachePath = path + "." + entry.fileExtension;
				subCacheFilename = mainFileName + "." + entry.fileExtension;
			}
			auto subCacheFile = MMappedFileAccessor::Open(m_dscView, m_dscView->GetFile()->GetSessionId(), subCachePath)->lock();

			dyld_cache_header subCacheHeader {};
			uint64_t headerSize = subCacheFile->ReadUInt32(16);
			if (headerSize > sizeof(dyld_cache_header))
			{
				m_logger->LogDebug("Header size is larger than expected (0x%llx), using default size (0x%llx)", headerSize,
					sizeof(dyld_cache_header));
				headerSize = sizeof(dyld_cache_header);
			}
			subCacheFile->Read(&subCacheHeader, 0, headerSize);

			dyld_cache_mapping_info subCacheMapping {};
			BackingCache subCache;
			subCache.isPrimary = false;
			subCache.path = subCachePath;

			for (size_t j = 0; j < subCacheHeader.mappingCount; j++)
			{
				subCacheFile->Read(&subCacheMapping, subCacheHeader.mappingOffset + (j * sizeof(subCacheMapping)),
					sizeof(subCacheMapping));
				std::pair<uint64_t, std::pair<uint64_t, uint64_t>> mapRawToAddrAndSize;
				mapRawToAddrAndSize.first = subCacheMapping.fileOffset;
				mapRawToAddrAndSize.second.first = subCacheMapping.address;
				mapRawToAddrAndSize.second.second = subCacheMapping.size;
				subCache.mappings.push_back(mapRawToAddrAndSize);
			}

			if (subCacheHeader.mappingCount == 1 && subCacheHeader.imagesCountOld == 0 && subCacheHeader.imagesCount == 0
				&& subCacheHeader.imagesTextOffset == 0)
			{
				auto pathBasename = subCachePath.substr(subCachePath.find_last_of("/\\") + 1);
				uint64_t address = subCacheMapping.address;
				uint64_t size = subCacheMapping.size;
				MemoryRegion stubIslandRegion;
				stubIslandRegion.start = address;
				stubIslandRegion.size = size;
				stubIslandRegion.prettyName = subCacheFilename + "::_stubs";
				stubIslandRegion.flags = (BNSegmentFlag)(BNSegmentFlag::SegmentReadable | BNSegmentFlag::SegmentExecutable);
				m_stubIslandRegions.push_back(stubIslandRegion);
			}

			m_backingCaches.push_back(subCache);
		}
		break;
	}
	case SplitCacheFormat:
	{
		dyld_cache_mapping_info mapping {};	 // We're going to reuse this for all of the mappings. We only need it
											 // briefly.
		BackingCache cache;
		cache.isPrimary = true;
		cache.path = path;

		for (size_t i = 0; i < primaryCacheHeader.mappingCount; i++)
		{
			baseFile->Read(&mapping, primaryCacheHeader.mappingOffset + (i * sizeof(mapping)), sizeof(mapping));
			std::pair<uint64_t, std::pair<uint64_t, uint64_t>> mapRawToAddrAndSize;
			mapRawToAddrAndSize.first = mapping.fileOffset;
			mapRawToAddrAndSize.second.first = mapping.address;
			mapRawToAddrAndSize.second.second = mapping.size;
			cache.mappings.push_back(mapRawToAddrAndSize);
		}
		m_backingCaches.push_back(cache);

		dyld_cache_image_info img {};

		for (size_t i = 0; i < primaryCacheHeader.imagesCount; i++)
		{
			baseFile->Read(&img, primaryCacheHeader.imagesOffset + (i * sizeof(img)), sizeof(img));
			auto iname = baseFile->ReadNullTermString(img.pathFileOffset);
			m_imageStarts[iname] = img.address;
		}

		if (primaryCacheHeader.branchPoolsCount)
		{
			std::vector<uint64_t> pool {};
			for (size_t i = 0; i < primaryCacheHeader.branchPoolsCount; i++)
			{
				m_imageStarts["dyld_shared_cache_branch_islands_" + std::to_string(i)] = baseFile->ReadULong(primaryCacheHeader.branchPoolsOffset + (i * m_dscView->GetAddressSize()));
			}
		}

		std::string mainFileName = base_name(path);
		if (auto projectFile = m_dscView->GetFile()->GetProjectFile())
			mainFileName = projectFile->GetName();
		auto subCacheCount = primaryCacheHeader.subCacheArrayCount;

		baseFile.reset();

		for (size_t i = 1; i <= subCacheCount; i++)
		{
			auto subCachePath = path + "." + std::to_string(i);
			auto subCacheFilename = mainFileName + "." + std::to_string(i);
			auto subCacheFile = MMappedFileAccessor::Open(m_dscView, m_dscView->GetFile()->GetSessionId(), subCachePath)->lock();

			dyld_cache_header subCacheHeader {};
			uint64_t headerSize = subCacheFile->ReadUInt32(16);
			if (headerSize > sizeof(dyld_cache_header))
			{
				m_logger->LogDebug("Header size is larger than expected (0x%llx), using default size (0x%llx)", headerSize,
					sizeof(dyld_cache_header));
				headerSize = sizeof(dyld_cache_header);
			}
			subCacheFile->Read(&subCacheHeader, 0, headerSize);

			BackingCache subCache;
			subCache.isPrimary = false;
			subCache.path = subCachePath;

			dyld_cache_mapping_info subCacheMapping {};

			for (size_t j = 0; j < subCacheHeader.mappingCount; j++)
			{
				subCacheFile->Read(&subCacheMapping, subCacheHeader.mappingOffset + (j * sizeof(subCacheMapping)),
					sizeof(subCacheMapping));
				std::pair<uint64_t, std::pair<uint64_t, uint64_t>> mapRawToAddrAndSize;
				mapRawToAddrAndSize.first = subCacheMapping.fileOffset;
				mapRawToAddrAndSize.second.first = subCacheMapping.address;
				mapRawToAddrAndSize.second.second = subCacheMapping.size;
				subCache.mappings.push_back(mapRawToAddrAndSize);
			}

			m_backingCaches.push_back(subCache);

			if (subCacheHeader.mappingCount == 1 && subCacheHeader.imagesCountOld == 0 && subCacheHeader.imagesCount == 0
				&& subCacheHeader.imagesTextOffset == 0)
			{
				auto pathBasename = subCachePath.substr(subCachePath.find_last_of("/\\") + 1);
				uint64_t address = subCacheMapping.address;
				uint64_t size = subCacheMapping.size;
				MemoryRegion stubIslandRegion;
				stubIslandRegion.start = address;
				stubIslandRegion.size = size;
				stubIslandRegion.prettyName = subCacheFilename + "::_stubs";
				stubIslandRegion.flags = (BNSegmentFlag)(BNSegmentFlag::SegmentReadable | BNSegmentFlag::SegmentExecutable);
				m_stubIslandRegions.push_back(stubIslandRegion);
			}
		}

		// Load .symbols subcache

		auto subCachePath = path + ".symbols";
		auto subCacheFile = MMappedFileAccessor::Open(m_dscView, m_dscView->GetFile()->GetSessionId(), subCachePath)->lock();

		dyld_cache_header subCacheHeader {};
		uint64_t headerSize = subCacheFile->ReadUInt32(16);
		if (headerSize > sizeof(dyld_cache_header))
		{
			m_logger->LogDebug("Header size is larger than expected (0x%llx), using default size (0x%llx)", headerSize,
				sizeof(dyld_cache_header));
			headerSize = sizeof(dyld_cache_header);
		}
		subCacheFile->Read(&subCacheHeader, 0, headerSize);

		dyld_cache_mapping_info subCacheMapping {};
		BackingCache subCache;

		for (size_t j = 0; j < subCacheHeader.mappingCount; j++)
		{
			subCacheFile->Read(&subCacheMapping, subCacheHeader.mappingOffset + (j * sizeof(subCacheMapping)),
				sizeof(subCacheMapping));
			std::pair<uint64_t, std::pair<uint64_t, uint64_t>> mapRawToAddrAndSize;
			mapRawToAddrAndSize.first = subCacheMapping.fileOffset;
			mapRawToAddrAndSize.second.first = subCacheMapping.address;
			mapRawToAddrAndSize.second.second = subCacheMapping.size;
			subCache.mappings.push_back(mapRawToAddrAndSize);
		}

		m_backingCaches.push_back(subCache);
		break;
	}
	case iOS16CacheFormat:
	{
		dyld_cache_mapping_info mapping {};

		BackingCache cache;
		cache.isPrimary = true;
		cache.path = path;

		for (size_t i = 0; i < primaryCacheHeader.mappingCount; i++)
		{
			baseFile->Read(&mapping, primaryCacheHeader.mappingOffset + (i * sizeof(mapping)), sizeof(mapping));
			std::pair<uint64_t, std::pair<uint64_t, uint64_t>> mapRawToAddrAndSize;
			mapRawToAddrAndSize.first = mapping.fileOffset;
			mapRawToAddrAndSize.second.first = mapping.address;
			mapRawToAddrAndSize.second.second = mapping.size;
			cache.mappings.push_back(mapRawToAddrAndSize);
		}

		m_backingCaches.push_back(cache);

		dyld_cache_image_info img {};

		for (size_t i = 0; i < primaryCacheHeader.imagesCount; i++)
		{
			baseFile->Read(&img, primaryCacheHeader.imagesOffset + (i * sizeof(img)), sizeof(img));
			auto iname = baseFile->ReadNullTermString(img.pathFileOffset);
			m_imageStarts[iname] = img.address;
		}

		if (primaryCacheHeader.branchPoolsCount)
		{
			std::vector<uint64_t> pool {};
			for (size_t i = 0; i < primaryCacheHeader.branchPoolsCount; i++)
			{
				m_imageStarts["dyld_shared_cache_branch_islands_" + std::to_string(i)] = baseFile->ReadULong(primaryCacheHeader.branchPoolsOffset + (i * m_dscView->GetAddressSize()));
			}
		}

		std::string mainFileName = base_name(path);
		if (auto projectFile = m_dscView->GetFile()->GetProjectFile())
			mainFileName = projectFile->GetName();
		auto subCacheCount = primaryCacheHeader.subCacheArrayCount;

		dyld_subcache_entry2 _entry {};

		std::vector<dyld_subcache_entry2> subCacheEntries;
		for (size_t i = 0; i < subCacheCount; i++)
		{
			baseFile->Read(&_entry, primaryCacheHeader.subCacheArrayOffset + (i * sizeof(dyld_subcache_entry2)),
				sizeof(dyld_subcache_entry2));
			subCacheEntries.push_back(_entry);
		}

		baseFile.reset();

		for (const auto& entry : subCacheEntries)
		{
			std::string subCachePath;
			std::string subCacheFilename;
			if (std::string(entry.fileExtension).find('.') != std::string::npos)
			{
				subCachePath = path + entry.fileExtension;
				subCacheFilename = mainFileName + entry.fileExtension;
			}
			else
			{
				subCachePath = path + "." + entry.fileExtension;
				subCacheFilename = mainFileName + "." + entry.fileExtension;
			}

			auto subCacheFile = MMappedFileAccessor::Open(m_dscView, m_dscView->GetFile()->GetSessionId(), subCachePath)->lock();

			dyld_cache_header subCacheHeader {};
			uint64_t headerSize = subCacheFile->ReadUInt32(16);
			if (headerSize > sizeof(dyld_cache_header))
			{
				m_logger->LogDebug("Header size is larger than expected (0x%llx), using default size (0x%llx)", headerSize,
					sizeof(dyld_cache_header));
				headerSize = sizeof(dyld_cache_header);
			}
			subCacheFile->Read(&subCacheHeader, 0, headerSize);

			dyld_cache_mapping_info subCacheMapping {};

			BackingCache subCache;
			subCache.isPrimary = false;
			subCache.path = subCachePath;

			for (size_t j = 0; j < subCacheHeader.mappingCount; j++)
			{
				subCacheFile->Read(&subCacheMapping, subCacheHeader.mappingOffset + (j * sizeof(subCacheMapping)),
					sizeof(subCacheMapping));

				std::pair<uint64_t, std::pair<uint64_t, uint64_t>> mapRawToAddrAndSize;
				mapRawToAddrAndSize.first = subCacheMapping.fileOffset;
				mapRawToAddrAndSize.second.first = subCacheMapping.address;
				mapRawToAddrAndSize.second.second = subCacheMapping.size;
				subCache.mappings.push_back(mapRawToAddrAndSize);

				if (subCachePath.find(".dylddata") != std::string::npos)
				{
					auto pathBasename = subCachePath.substr(subCachePath.find_last_of("/\\") + 1);
					uint64_t address = subCacheMapping.address;
					uint64_t size = subCacheMapping.size;
					MemoryRegion dyldDataRegion;
					dyldDataRegion.start = address;
					dyldDataRegion.size = size;
					dyldDataRegion.prettyName = subCacheFilename + "::_data" + std::to_string(j);
					dyldDataRegion.flags = (BNSegmentFlag)(BNSegmentFlag::SegmentReadable);
					m_dyldDataRegions.push_back(dyldDataRegion);
				}
			}

			m_backingCaches.push_back(subCache);

			if (subCacheHeader.mappingCount == 1 && subCacheHeader.imagesCountOld == 0 && subCacheHeader.imagesCount == 0
				&& subCacheHeader.imagesTextOffset == 0)
			{
				auto pathBasename = subCachePath.substr(subCachePath.find_last_of("/\\") + 1);
				uint64_t address = subCacheMapping.address;
				uint64_t size = subCacheMapping.size;
				MemoryRegion stubIslandRegion;
				stubIslandRegion.start = address;
				stubIslandRegion.size = size;
				stubIslandRegion.prettyName = subCacheFilename + "::_stubs";
				stubIslandRegion.flags = (BNSegmentFlag)(BNSegmentFlag::SegmentReadable | BNSegmentFlag::SegmentExecutable);
				m_stubIslandRegions.push_back(stubIslandRegion);
			}
		}

		// Load .symbols subcache
		try
		{
			auto subCachePath = path + ".symbols";
			auto subCacheFile = MMappedFileAccessor::Open(m_dscView, m_dscView->GetFile()->GetSessionId(), subCachePath)->lock();
			dyld_cache_header subCacheHeader {};
			uint64_t headerSize = subCacheFile->ReadUInt32(16);
			if (subCacheFile->ReadUInt32(16) > sizeof(dyld_cache_header))
			{
				m_logger->LogDebug("Header size is larger than expected, using default size");
				headerSize = sizeof(dyld_cache_header);
			}
			subCacheFile->Read(&subCacheHeader, 0, headerSize);

			BackingCache subCache;
			subCache.isPrimary = false;
			subCache.path = subCachePath;

			dyld_cache_mapping_info subCacheMapping {};

			for (size_t j = 0; j < subCacheHeader.mappingCount; j++)
			{
				subCacheFile->Read(&subCacheMapping, subCacheHeader.mappingOffset + (j * sizeof(subCacheMapping)),
					sizeof(subCacheMapping));
				std::pair<uint64_t, std::pair<uint64_t, uint64_t>> mapRawToAddrAndSize;
				mapRawToAddrAndSize.first = subCacheMapping.fileOffset;
				mapRawToAddrAndSize.second.first = subCacheMapping.address;
				mapRawToAddrAndSize.second.second = subCacheMapping.size;
				subCache.mappings.push_back(mapRawToAddrAndSize);
			}

			m_backingCaches.push_back(subCache);
		}
		catch (...)
		{}
		break;
	}
	}
	baseFile.reset();
	progressMutex.lock();
	progressMap[m_dscView->GetFile()->GetSessionId()] = LoadProgressLoadingImages;
	progressMutex.unlock();

	// We have set up enough metadata to map VM now.

	auto vm = GetVMMap(true);
	if (!vm)
	{
		m_logger->LogError("Failed to map VM pages for Shared Cache on initial load, this is fatal.");
		return;
	}
	for (const auto &start : m_imageStarts)
	{
		try {
			auto imageHeader = SharedCache::LoadHeaderForAddress(vm, start.second, start.first);
			if (imageHeader)
			{
				if (imageHeader->linkeditPresent && vm->AddressIsMapped(imageHeader->linkeditSegment.vmaddr))
				{
					auto mapping = vm->MappingAtAddress(imageHeader->linkeditSegment.vmaddr);
					imageHeader->exportTriePath = mapping.first.filePath;
				}
				m_headers[start.second] = imageHeader.value();
				CacheImage image;
				image.installName = start.first;
				image.headerLocation = start.second;
				for (const auto& segment : imageHeader->segments)
				{
					char segName[17];
					memcpy(segName, segment.segname, 16);
					segName[16] = 0;
					MemoryRegion sectionRegion;
					sectionRegion.prettyName = imageHeader.value().identifierPrefix + "::" + std::string(segName);
					sectionRegion.start = segment.vmaddr;
					sectionRegion.size = segment.vmsize;
					uint32_t flags = 0;
					if (segment.initprot & MACHO_VM_PROT_READ)
						flags |= SegmentReadable;
					if (segment.initprot & MACHO_VM_PROT_WRITE)
						flags |= SegmentWritable;
					if (segment.initprot & MACHO_VM_PROT_EXECUTE)
						flags |= SegmentExecutable;
					if (((segment.initprot & MACHO_VM_PROT_WRITE) == 0) &&
						((segment.maxprot & MACHO_VM_PROT_WRITE) == 0))
						flags |= SegmentDenyWrite;
					if (((segment.initprot & MACHO_VM_PROT_EXECUTE) == 0) &&
						((segment.maxprot & MACHO_VM_PROT_EXECUTE) == 0))
						flags |= SegmentDenyExecute;

					// if we're positive we have an entry point for some reason, force the segment
					// executable. this helps with kernel images.
					for (auto &entryPoint: imageHeader->m_entryPoints)
						if (segment.vmaddr <= entryPoint && (entryPoint < (segment.vmaddr + segment.filesize)))
							flags |= SegmentExecutable;

					sectionRegion.flags = (BNSegmentFlag)flags;
					image.regions.push_back(sectionRegion);
				}
				m_images.push_back(image);
			}
			else
			{
				m_logger->LogError("Failed to load Mach-O header for %s", start.first.c_str());
			}
		}
		catch (std::exception& ex)
		{
			m_logger->LogError("Failed to load Mach-O header for %s: %s", start.first.c_str(), ex.what());
		}
	}

	m_logger->LogInfo("Loaded %d Mach-O headers", m_headers.size());

	for (const auto& cache : m_backingCaches)
	{
		size_t i = 0;
		for (const auto& mapping : cache.mappings)
		{
			MemoryRegion region;
			region.start = mapping.second.first;
			region.size = mapping.second.second;
			region.prettyName = base_name(cache.path) + "::" + std::to_string(i);
			// FIXME flags!!! BackingCache.mapping needs refactored to store this information!
			region.flags = (BNSegmentFlag)(BNSegmentFlag::SegmentReadable | BNSegmentFlag::SegmentExecutable);
			m_nonImageRegions.push_back(region);
			i++;
		}
	}

	// Iterate through each Mach-O header
	if (!m_dyldDataRegions.empty())
	{
		for (const auto& [headerKey, header] : m_headers)
		{
			// Iterate through each segment of the header
			for (const auto& segment : header.segments)
			{
				uint64_t segmentStart = segment.vmaddr;
				uint64_t segmentEnd = segmentStart + segment.vmsize;

				// Iterate through each region in m_dyldDataRegions
				for (auto it = m_dyldDataRegions.begin(); it != m_dyldDataRegions.end();)
				{
					uint64_t regionStart = it->start;
					uint64_t regionSize = it->size;
					uint64_t regionEnd = regionStart + regionSize;

					// Check if the region overlaps with the segment
					if (segmentStart < regionEnd && segmentEnd > regionStart)
					{
						// Split the region into two, removing the overlapped portion
						std::vector<MemoryRegion> newRegions;

						// Part before the overlap
						if (regionStart < segmentStart)
						{
							MemoryRegion newRegion;
							newRegion.start = regionStart;
							newRegion.size = segmentStart - regionStart;
							newRegion.prettyName = it->prettyName;
							newRegions.push_back(newRegion);
						}

						// Part after the overlap
						if (regionEnd > segmentEnd)
						{
							MemoryRegion newRegion;
							newRegion.start = segmentEnd;
							newRegion.size = regionEnd - segmentEnd;
							newRegion.prettyName = it->prettyName;
							newRegions.push_back(newRegion);
						}

						// Erase the original region
						it = m_dyldDataRegions.erase(it);

						// Insert the new regions (if any)
						for (const auto& newRegion : newRegions)
						{
							it = m_dyldDataRegions.insert(it, newRegion);
							++it;  // Move iterator to the next position
						}
					}
					else
					{
						++it;  // No overlap, move to the next region
					}
				}
			}
		}
	}

	// Iterate through each Mach-O header
	if (!m_nonImageRegions.empty())
	{
		for (const auto& [headerKey, header] : m_headers)
		{
			// Iterate through each segment of the header
			for (const auto& segment : header.segments)
			{
				uint64_t segmentStart = segment.vmaddr;
				uint64_t segmentEnd = segmentStart + segment.vmsize;

				// Iterate through each region in m_dyldDataRegions
				for (auto it = m_nonImageRegions.begin(); it != m_nonImageRegions.end();)
				{
					uint64_t regionStart = it->start;
					uint64_t regionSize = it->size;
					uint64_t regionEnd = regionStart + regionSize;

					// Check if the region overlaps with the segment
					if (segmentStart < regionEnd && segmentEnd > regionStart)
					{
						// Split the region into two, removing the overlapped portion
						std::vector<MemoryRegion> newRegions;

						// Part before the overlap
						if (regionStart < segmentStart)
						{
							MemoryRegion newRegion;
							newRegion.start = regionStart;
							newRegion.size = segmentStart - regionStart;
							newRegion.prettyName = it->prettyName;
							newRegions.push_back(newRegion);
						}

						// Part after the overlap
						if (regionEnd > segmentEnd)
						{
							MemoryRegion newRegion;
							newRegion.start = segmentEnd;
							newRegion.size = regionEnd - segmentEnd;
							newRegion.prettyName = it->prettyName;
							newRegions.push_back(newRegion);
						}

						// Erase the original region
						it = m_nonImageRegions.erase(it);

						// Insert the new regions (if any)
						for (const auto& newRegion : newRegions)
						{
							it = m_nonImageRegions.insert(it, newRegion);
							++it;  // Move iterator to the next position
						}
					}
					else
					{
						++it;  // No overlap, move to the next region
					}
				}
			}
		}
	}
	SaveToDSCView();

	m_logger->LogDebug("Finished initial load of Shared Cache");

	progressMutex.lock();
	progressMap[m_dscView->GetFile()->GetSessionId()] = LoadProgressFinished;
	progressMutex.unlock();
}

std::shared_ptr<VM> SharedCache::GetVMMap(bool mapPages)
{
	std::shared_ptr<VM> vm = std::make_shared<VM>(0x1000);

	if (mapPages)
	{
		for (const auto& cache : m_backingCaches)
		{
			for (const auto& mapping : cache.mappings)
			{
				vm->MapPages(m_dscView, m_dscView->GetFile()->GetSessionId(), mapping.second.first, mapping.first, mapping.second.second, cache.path,
					[this, vm=vm](std::shared_ptr<MMappedFileAccessor> mmap){
						ParseAndApplySlideInfoForFile(mmap);
					});
			}
		}
	}

	return vm;
}


void SharedCache::DeserializeFromRawView()
{
	if (m_dscView->QueryMetadata(SharedCacheMetadataTag))
	{
		std::unique_lock<std::recursive_mutex> viewStateCacheLock(viewStateMutex);
		if (viewStateCache.find(m_dscView->GetFile()->GetSessionId()) != viewStateCache.end())
		{
			auto c = viewStateCache[m_dscView->GetFile()->GetSessionId()];
			m_imageStarts = c.m_imageStarts;
			m_cacheFormat = c.m_cacheFormat;
			m_backingCaches = c.m_backingCaches;
			m_viewState = c.m_viewState;
			m_headers = c.m_headers;
			m_images = c.m_images;
			m_regionsMappedIntoMemory = c.m_regionsMappedIntoMemory;
			m_stubIslandRegions = c.m_stubIslandRegions;
			m_dyldDataRegions = c.m_dyldDataRegions;
			m_nonImageRegions = c.m_nonImageRegions;
			m_baseFilePath = c.m_baseFilePath;
			m_exportInfos = c.m_exportInfos;
			m_symbolInfos = c.m_symbolInfos;
			m_metadataValid = true;
		}
		else
		{
			LoadFromString(m_dscView->GetStringMetadata(SharedCacheMetadataTag));
		}
		if (!m_metadataValid)
		{
			m_logger->LogError("Failed to deserialize Shared Cache metadata");
			m_viewState = DSCViewStateUnloaded;
		}
	}
	else
	{
		m_metadataValid = true;
		m_viewState = DSCViewStateUnloaded;
		m_images.clear(); // fixme ??
	}
}


std::string to_hex_string(uint64_t value)
{
	std::stringstream ss;
	ss << std::hex << value;
	return ss.str();
}


void SharedCache::ParseAndApplySlideInfoForFile(std::shared_ptr<MMappedFileAccessor> file)
{
	if (file->SlideInfoWasApplied())
		return;
	std::vector<std::pair<uint64_t, uint64_t>> rewrites;

	dyld_cache_header baseHeader;
	file->Read(&baseHeader, 0, sizeof(dyld_cache_header));
	uint64_t base = UINT64_MAX;
	for (const auto& backingCache : m_backingCaches)
	{
		for (const auto& mapping : backingCache.mappings)
		{
			if (mapping.second.first < base)
			{
				base = mapping.second.first;
				break;
			}
		}
	}

	std::vector<std::pair<uint64_t, MappingInfo>> mappings;

	if (baseHeader.slideInfoOffsetUnused)
	{
		// Legacy

		auto slideInfoOff = baseHeader.slideInfoOffsetUnused;
		auto slideInfoVersion = file->ReadUInt32(slideInfoOff);
		if (slideInfoVersion != 2 && slideInfoVersion != 3)
		{
			abort();
		}

		MappingInfo map;

		file->Read(&map.mappingInfo, baseHeader.mappingOffset + sizeof(dyld_cache_mapping_info), sizeof(dyld_cache_mapping_info));
		map.file = file;
		map.slideInfoVersion = slideInfoVersion;
		if (map.slideInfoVersion == 2)
			file->Read(&map.slideInfoV2, slideInfoOff, sizeof(dyld_cache_slide_info_v2));
		else if (map.slideInfoVersion == 3)
			file->Read(&map.slideInfoV3, slideInfoOff, sizeof(dyld_cache_slide_info_v3));

		mappings.emplace_back(slideInfoOff, map);
	}
	else
	{
		dyld_cache_header targetHeader;
		file->Read(&targetHeader, 0, sizeof(dyld_cache_header));

		if (targetHeader.mappingWithSlideCount == 0)
		{
			m_logger->LogDebug("No mappings with slide info found");
		}

		for (auto i = 0; i < targetHeader.mappingWithSlideCount; i++)
		{
			dyld_cache_mapping_and_slide_info mappingAndSlideInfo;
			file->Read(&mappingAndSlideInfo, targetHeader.mappingWithSlideOffset + (i * sizeof(dyld_cache_mapping_and_slide_info)), sizeof(dyld_cache_mapping_and_slide_info));
			if (mappingAndSlideInfo.slideInfoFileOffset)
			{
				MappingInfo map;
				map.file = file;
				if (mappingAndSlideInfo.size == 0)
					continue;
				map.slideInfoVersion = file->ReadUInt32(mappingAndSlideInfo.slideInfoFileOffset);
				m_logger->LogDebug("Slide Info Version: %d", map.slideInfoVersion);
				map.mappingInfo.address = mappingAndSlideInfo.address;
				map.mappingInfo.size = mappingAndSlideInfo.size;
				map.mappingInfo.fileOffset = mappingAndSlideInfo.fileOffset;
				if (map.slideInfoVersion == 2)
				{
					file->Read(
						&map.slideInfoV2, mappingAndSlideInfo.slideInfoFileOffset, sizeof(dyld_cache_slide_info_v2));
				}
				else if (map.slideInfoVersion == 3)
				{
					file->Read(
						&map.slideInfoV3, mappingAndSlideInfo.slideInfoFileOffset, sizeof(dyld_cache_slide_info_v3));
					map.slideInfoV3.auth_value_add = base;
				}
				else if (map.slideInfoVersion == 5)
				{
					file->Read(
						&map.slideInfoV5, mappingAndSlideInfo.slideInfoFileOffset, sizeof(dyld_cache_slide_info5));
					map.slideInfoV5.value_add = base;
				}
				else
				{
					m_logger->LogError("Unknown slide info version: %d", map.slideInfoVersion);
					continue;
				}

				uint64_t slideInfoOffset = mappingAndSlideInfo.slideInfoFileOffset;
				mappings.emplace_back(slideInfoOffset, map);
				m_logger->LogDebug("Filename: %s", file->Path().c_str());
				m_logger->LogDebug("Slide Info Offset: 0x%llx", slideInfoOffset);
				m_logger->LogDebug("Mapping Address: 0x%llx", map.mappingInfo.address);
				m_logger->LogDebug("Slide Info v", map.slideInfoVersion);
			}
		}
	}

	if (mappings.empty())
	{
		m_logger->LogDebug("No slide info found");
		file->SetSlideInfoWasApplied(true);
		return;
	}

	for (const auto& [off, mapping] : mappings)
	{
		m_logger->LogDebug("Slide Info Version: %d", mapping.slideInfoVersion);
		uint64_t pageStartsOffset = off;
		uint64_t pageStartCount;
		uint64_t pageSize;
		std::vector<uint64_t> pageStartFileOffsets;

		if (mapping.slideInfoVersion == 2)
		{
			pageStartsOffset += mapping.slideInfoV2.page_starts_offset;
			pageStartCount = mapping.slideInfoV2.page_starts_count;
			pageSize = mapping.slideInfoV2.page_size;

			pageStartFileOffsets.reserve(pageStartCount);
			size_t cursor = pageStartsOffset;

			for (size_t i = 0; i < pageStartCount; i++)
			{
				try
				{
					uint64_t pageStart = mapping.file->ReadUShort(cursor) * 4;
					cursor += 2;
					if (pageStart & 0x4000)
						continue;
					pageStartFileOffsets.push_back(mapping.mappingInfo.fileOffset + (pageSize * i) + pageStart);
				}
				catch (MappingReadException& ex)
				{

				}
			}
		}
		else if (mapping.slideInfoVersion == 3) {
			// Slide Info Version 3 Logic
			pageStartsOffset += sizeof(dyld_cache_slide_info_v3);
			pageStartCount = mapping.slideInfoV3.page_starts_count;
			pageSize = mapping.slideInfoV3.page_size;

			pageStartFileOffsets.reserve(pageStartCount);
			size_t cursor = pageStartsOffset;

			for (size_t i = 0; i < pageStartCount; i++)
			{
				try
				{
					uint64_t pageStart = mapping.file->ReadUShort(cursor);
					cursor += 2;
					if (pageStart & 0x4000)
						continue;
					pageStartFileOffsets.push_back(mapping.mappingInfo.fileOffset + (pageSize * i) + pageStart);
				}
				catch (MappingReadException& ex)
				{
					m_logger->LogError("Failed to read slide info at 0x%llx\n", cursor);
				}
			}
		}
		else if (mapping.slideInfoVersion == 5)
		{
			pageStartsOffset += sizeof(dyld_cache_slide_info5);
			pageStartCount = mapping.slideInfoV5.page_starts_count;
			m_logger->LogDebug("Page Start Count: %d", pageStartCount);
			pageSize = mapping.slideInfoV5.page_size;
			auto cursor = pageStartsOffset;
			for (size_t i = 0; i < pageStartCount; i++)
			{
				try
				{
					uint64_t pageStart = mapping.file->ReadUShort(cursor);
					cursor += 2;
					if (pageStart == DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE)
						continue;
					pageStartFileOffsets.push_back(mapping.mappingInfo.fileOffset + (pageSize * i) + pageStart);
				}
				catch (MappingReadException& ex)
				{
					m_logger->LogError("Failed to read slide info at 0x%llx\n", cursor);
				}
			}
		}
		if (pageStartFileOffsets.empty())
		{
			m_logger->LogDebug("No page start file offsets found");
		}
		for (auto pageStart : pageStartFileOffsets)
		{
			if (mapping.slideInfoVersion == 2)
			{
				auto deltaMask = mapping.slideInfoV2.delta_mask;
				auto valueMask = ~deltaMask;
				auto valueAdd = mapping.slideInfoV2.value_add;

				auto deltaShift = count_trailing_zeros(deltaMask) - 2;

				uint64_t delta = 1;
				uint64_t loc = pageStart;
				while (delta != 0)
				{
					try {
						uint64_t rawValue = file->ReadULong(loc);
						delta = (rawValue & deltaMask) >> deltaShift;
						uint64_t value = (rawValue & valueMask);
						if (valueMask != 0)
						{
							value += valueAdd;
						}
						rewrites.emplace_back(loc, value);
					}
					catch (MappingReadException& ex)
					{
						m_logger->LogError("Failed to read slide info at 0x%llx\n", loc);
						delta = 0;
					}
					loc += delta;
				}
			}
			else if (mapping.slideInfoVersion == 3)
			{
				uint64_t loc = pageStart;
				uint64_t delta = 1;
				while (delta != 0)
				{
					dyld_cache_slide_pointer3 slideInfo;
					try
					{
						file->Read(&slideInfo, loc, 8);
						delta = slideInfo.plain.offsetToNextPointer * 8;

						if (slideInfo.auth.authenticated)
						{
							uint64_t value = slideInfo.auth.offsetFromSharedCacheBase;
							value += mapping.slideInfoV3.auth_value_add;
							rewrites.emplace_back(loc, value);
						}
						else
						{
							uint64_t value51 = slideInfo.plain.pointerValue;
							uint64_t top8Bits = value51 & 0x0007F80000000000;
							uint64_t bottom43Bits = value51 & 0x000007FFFFFFFFFF;
							uint64_t value = (uint64_t)top8Bits << 13 | bottom43Bits;
							rewrites.emplace_back(loc, value);
						}
						loc += delta;
					}
					catch (MappingReadException& ex)
					{
						m_logger->LogError("Failed to read slide info at 0x%llx\n", loc);
						delta = 0;
					}
				}
			}
			else if (mapping.slideInfoVersion == 5)
			{
				uint64_t loc = pageStart;
				uint64_t delta = 1;
				while (delta != 0)
				{
					dyld_cache_slide_pointer5 slideInfo;
					try
					{
						file->Read(&slideInfo, loc, 8);
						delta = slideInfo.regular.next * 8;
						if (slideInfo.auth.auth)
						{
							uint64_t value = slideInfo.auth.runtimeOffset + mapping.slideInfoV5.value_add;
							rewrites.emplace_back(loc, value);
						}
						else
						{
							uint64_t value = base + slideInfo.regular.runtimeOffset;
							rewrites.emplace_back(loc, value);
						}
						loc += delta;
					}
					catch (MappingReadException& ex)
					{
						m_logger->LogError("Failed to read slide info at 0x%llx\n", loc);
						delta = 0;
					}
				}
			}
		}
	}
	for (const auto& [loc, value] : rewrites)
	{
		file->WritePointer(loc, value);
#ifdef SLIDEINFO_DEBUG_TAGS
		uint64_t vmAddr = 0;
		{
			for (uint64_t off = baseHeader.mappingOffset; off < baseHeader.mappingOffset + baseHeader.mappingCount * sizeof(dyld_cache_mapping_info); off += sizeof(dyld_cache_mapping_info))
			{
				dyld_cache_mapping_info mapping;
				file->Read(&mapping, off, sizeof(dyld_cache_mapping_info));
				if (mapping.fileOffset <= loc && loc < mapping.fileOffset + mapping.size)
				{
					vmAddr = mapping.address + (loc - mapping.fileOffset);
					break;
				}
			}
		}
		Ref<TagType> type = m_dscView->GetTagType("slideinfo");
		if (!type)
		{
			m_dscView->AddTagType(new TagType(m_dscView, "slideinfo", "\xF0\x9F\x9A\x9E"));
			type = m_dscView->GetTagType("slideinfo");
		}
		m_dscView->AddAutoDataTag(vmAddr, new Tag(type, "0x" + to_hex_string(file->ReadULong(loc)) + " => 0x" + to_hex_string(value)));
#endif
	}
	m_logger->LogDebug("Applied slide info for %s (0x%llx rewrites)", file->Path().c_str(), rewrites.size());
	file->SetSlideInfoWasApplied(true);
}


SharedCache::SharedCache(BinaryNinja::Ref<BinaryNinja::BinaryView> dscView) : m_dscView(dscView)
{
	if (dscView->GetTypeName() != VIEW_NAME)
	{
		// Unreachable?
		m_logger->LogError("Attempted to create SharedCache object from non-Shared Cache view");
		return;
	}
	sharedCacheReferences++;
	INIT_SHAREDCACHE_API_OBJECT()
	m_logger = LogRegistry::GetLogger("SharedCache", dscView->GetFile()->GetSessionId());
	DeserializeFromRawView();
	if (!m_metadataValid)
		return;
	if (m_viewState == DSCViewStateUnloaded)
	{
		if (m_viewState == DSCViewStateUnloaded)
		{
			std::unique_lock<std::mutex> lock(viewSpecificMutexes[m_dscView->GetFile()->GetSessionId()].viewOperationsThatInfluenceMetadataMutex);
			try {
				PerformInitialLoad();
			}
			catch (...)
			{
				m_logger->LogError("Failed to perform initial load of Shared Cache");
			}

			auto settings = m_dscView->GetLoadSettings(VIEW_NAME);
			bool autoLoadLibsystem = true;
			if (settings && settings->Contains("loader.dsc.autoLoadLibSystem"))
			{
				autoLoadLibsystem = settings->Get<bool>("loader.dsc.autoLoadLibSystem", m_dscView);
			}
			if (autoLoadLibsystem)
			{
				for (const auto& [_, header] : m_headers)
				{
					if (header.installName.find("libsystem_c.dylib") != std::string::npos)
					{
						lock.unlock();
						m_logger->LogInfo("Loading core libsystem_c.dylib library");
						LoadImageWithInstallName(header.installName);
						lock.lock();
						break;
					}
				}
			}
			m_viewState = DSCViewStateLoaded;
			SaveToDSCView();
		}
	}
	else
	{
		progressMutex.lock();
		progressMap[m_dscView->GetFile()->GetSessionId()] = LoadProgressFinished;
		progressMutex.unlock();
	}
}

SharedCache::~SharedCache() {
	std::unique_lock<std::mutex> lock(viewSpecificMutexes[m_dscView->GetFile()->GetSessionId()].viewOperationsThatInfluenceMetadataMutex);
	sharedCacheReferences--;
}

SharedCache* SharedCache::GetFromDSCView(BinaryNinja::Ref<BinaryNinja::BinaryView> dscView)
{
	if (dscView->GetTypeName() != VIEW_NAME)
		return nullptr;
	try {
		return new SharedCache(dscView);
	}
	catch (...)
	{
		return nullptr;
	}
}

std::optional<uint64_t> SharedCache::GetImageStart(std::string installName)
{
	for (const auto& [name, start] : m_imageStarts)
	{
		if (name == installName)
		{
			return start;
		}
	}
	return {};
}

std::optional<SharedCacheMachOHeader> SharedCache::HeaderForAddress(uint64_t address)
{
	// We _could_ mark each page with the image start? :grimacing emoji:
	// But that'd require mapping pages :grimacing emoji: :grimacing emoji:
	// There's not really any other hacks that could make this faster, that I can think of...
	for (const auto& [start, header] : m_headers)
	{
		for (const auto& segment : header.segments)
		{
			if (segment.vmaddr <= address && segment.vmaddr + segment.vmsize > address)
			{
				return header;
			}
		}
	}
	return {};
}

std::string SharedCache::NameForAddress(uint64_t address)
{
	for (const auto& stubIsland : m_stubIslandRegions)
	{
		if (stubIsland.start <= address && stubIsland.start + stubIsland.size > address)
		{
			return stubIsland.prettyName;
		}
	}
	for (const auto& dyldData : m_dyldDataRegions)
	{
		if (dyldData.start <= address && dyldData.start + dyldData.size > address)
		{
			return dyldData.prettyName;
		}
	}
	for (const auto& nonImageRegion : m_nonImageRegions)
	{
		if (nonImageRegion.start <= address && nonImageRegion.start + nonImageRegion.size > address)
		{
			return nonImageRegion.prettyName;
		}
	}
	if (auto header = HeaderForAddress(address))
	{
		for (const auto& section : header->sections)
		{
			if (section.addr <= address && section.addr + section.size > address)
			{
				char sectionName[17];
				strncpy(sectionName, section.sectname, 16);
				sectionName[16] = '\0';
				return header->identifierPrefix + "::" + sectionName;
			}
		}
	}
	return "";
}

std::string SharedCache::ImageNameForAddress(uint64_t address)
{
	if (auto header = HeaderForAddress(address))
	{
		return header->identifierPrefix;
	}
	return "";
}

bool SharedCache::LoadImageContainingAddress(uint64_t address)
{
	for (const auto& [start, header] : m_headers)
	{
		for (const auto& segment : header.segments)
		{
			if (segment.vmaddr <= address && segment.vmaddr + segment.vmsize > address)
			{
				return LoadImageWithInstallName(header.installName);
			}
		}
	}

	return false;
}

bool SharedCache::LoadSectionAtAddress(uint64_t address)
{
	std::unique_lock<std::mutex> lock(viewSpecificMutexes[m_dscView->GetFile()->GetSessionId()].viewOperationsThatInfluenceMetadataMutex);
	DeserializeFromRawView();
	auto vm = GetVMMap();
	if (!vm)
	{
		m_logger->LogError("Failed to map VM pages for Shared Cache.");
		return false;
	}

	SharedCacheMachOHeader targetHeader;
	CacheImage* targetImage = nullptr;
	MemoryRegion* targetSegment = nullptr;

	for (auto& image : m_images)
	{
		for (auto& region : image.regions)
		{
			if (region.start <= address && region.start + region.size > address)
			{
				targetHeader = m_headers[image.headerLocation];
				targetImage = &image;
				targetSegment = &region;
				break;
			}
		}
		if (targetSegment)
			break;
	}
	if (!targetSegment)
	{
		for (auto& stubIsland : m_stubIslandRegions)
		{
			if (stubIsland.start <= address && stubIsland.start + stubIsland.size > address)
			{
				if (stubIsland.loaded)
				{
					return true;
				}
				m_logger->LogInfo("Loading stub island %s @ 0x%llx", stubIsland.prettyName.c_str(), stubIsland.start);
				auto targetFile = vm->MappingAtAddress(stubIsland.start).first.fileAccessor->lock();
				ParseAndApplySlideInfoForFile(targetFile);
				auto reader = VMReader(vm);
				auto buff = reader.ReadBuffer(stubIsland.start, stubIsland.size);
				auto rawViewEnd = m_dscView->GetParentView()->GetEnd();

				auto name = stubIsland.prettyName;
				m_dscView->GetParentView()->GetParentView()->WriteBuffer(
					m_dscView->GetParentView()->GetParentView()->GetEnd(), buff);
				m_dscView->GetParentView()->AddAutoSegment(rawViewEnd, stubIsland.size, rawViewEnd, stubIsland.size,
					SegmentReadable | SegmentExecutable);
				m_dscView->AddUserSegment(stubIsland.start, stubIsland.size, rawViewEnd, stubIsland.size,
					SegmentReadable | SegmentExecutable);
				m_dscView->AddUserSection(name, stubIsland.start, stubIsland.size, ReadOnlyCodeSectionSemantics);
				m_dscView->WriteBuffer(stubIsland.start, buff);

				stubIsland.loaded = true;

				stubIsland.rawViewOffsetIfLoaded = rawViewEnd;

				m_regionsMappedIntoMemory.push_back(stubIsland);

				SaveToDSCView();

				m_dscView->AddAnalysisOption("linearsweep");
				m_dscView->UpdateAnalysis();

				return true;
			}
		}

		for (auto& dyldData : m_dyldDataRegions)
		{
			if (dyldData.start <= address && dyldData.start + dyldData.size > address)
			{
				if (dyldData.loaded)
				{
					return true;
				}
				m_logger->LogInfo("Loading dyld data %s", dyldData.prettyName.c_str());
				auto targetFile = vm->MappingAtAddress(dyldData.start).first.fileAccessor->lock();
				ParseAndApplySlideInfoForFile(targetFile);
				auto reader = VMReader(vm);
				auto buff = reader.ReadBuffer(dyldData.start, dyldData.size);
				auto rawViewEnd = m_dscView->GetParentView()->GetEnd();

				auto name = dyldData.prettyName;
				m_dscView->GetParentView()->GetParentView()->WriteBuffer(
					m_dscView->GetParentView()->GetParentView()->GetEnd(), buff);
				m_dscView->GetParentView()->WriteBuffer(rawViewEnd, buff);
				m_dscView->GetParentView()->AddAutoSegment(rawViewEnd, dyldData.size, rawViewEnd, dyldData.size,
					SegmentReadable);
				m_dscView->AddUserSegment(dyldData.start, dyldData.size, rawViewEnd, dyldData.size, SegmentReadable);
				m_dscView->AddUserSection(name, dyldData.start, dyldData.size, ReadOnlyDataSectionSemantics);
				m_dscView->WriteBuffer(dyldData.start, buff);

				dyldData.loaded = true;
				dyldData.rawViewOffsetIfLoaded = rawViewEnd;

				m_regionsMappedIntoMemory.push_back(dyldData);

				SaveToDSCView();

				m_dscView->AddAnalysisOption("linearsweep");
				m_dscView->UpdateAnalysis();

				return true;
			}
		}

		for (auto& region : m_nonImageRegions)
		{
			if (region.start <= address && region.start + region.size > address)
			{
				if (region.loaded)
				{
					return true;
				}
				m_logger->LogInfo("Loading non-image region %s", region.prettyName.c_str());
				auto targetFile = vm->MappingAtAddress(region.start).first.fileAccessor->lock();
				ParseAndApplySlideInfoForFile(targetFile);
				auto reader = VMReader(vm);
				auto buff = reader.ReadBuffer(region.start, region.size);
				auto rawViewEnd = m_dscView->GetParentView()->GetEnd();

				auto name = region.prettyName;
				m_dscView->GetParentView()->GetParentView()->WriteBuffer(
					m_dscView->GetParentView()->GetParentView()->GetEnd(), buff);
				m_dscView->GetParentView()->WriteBuffer(rawViewEnd, buff);
				m_dscView->GetParentView()->AddAutoSegment(rawViewEnd, region.size, rawViewEnd, region.size, region.flags);
				m_dscView->AddUserSegment(region.start, region.size, rawViewEnd, region.size, region.flags);
				m_dscView->AddUserSection(name, region.start, region.size, ReadOnlyCodeSectionSemantics);
				m_dscView->WriteBuffer(region.start, buff);

				region.loaded = true;
				region.rawViewOffsetIfLoaded = rawViewEnd;

				m_regionsMappedIntoMemory.push_back(region);

				SaveToDSCView();

				m_dscView->AddAnalysisOption("linearsweep");
				m_dscView->UpdateAnalysis();

				return true;
			}
		}

		m_logger->LogError("Failed to find a segment containing address 0x%llx", address);
		return false;
	}

	auto id = m_dscView->BeginUndoActions();
	auto rawViewEnd = m_dscView->GetParentView()->GetEnd();
	auto reader = VMReader(vm);

	m_logger->LogDebug("Partial loading image %s", targetHeader.installName.c_str());

	auto targetFile = vm->MappingAtAddress(targetSegment->start).first.fileAccessor->lock();
	ParseAndApplySlideInfoForFile(targetFile);
	auto buff = reader.ReadBuffer(targetSegment->start, targetSegment->size);
	m_dscView->GetParentView()->GetParentView()->WriteBuffer(
		m_dscView->GetParentView()->GetParentView()->GetEnd(), buff);
	m_dscView->GetParentView()->WriteBuffer(rawViewEnd, buff);
	m_dscView->GetParentView()->AddAutoSegment(
		rawViewEnd, targetSegment->size, rawViewEnd, targetSegment->size, SegmentReadable);
	m_dscView->AddUserSegment(
		targetSegment->start, targetSegment->size, rawViewEnd, targetSegment->size, targetSegment->flags);
	m_dscView->WriteBuffer(targetSegment->start, buff);

	targetSegment->loaded = true;
	targetSegment->rawViewOffsetIfLoaded = rawViewEnd;

	m_regionsMappedIntoMemory.push_back(*targetSegment);

	SaveToDSCView();

	if (!targetSegment->headerInitialized)
	{
		SharedCache::InitializeHeader(m_dscView, vm.get(), targetHeader, {targetSegment});
	}

	m_dscView->AddAnalysisOption("linearsweep");
	m_dscView->UpdateAnalysis();

	m_dscView->CommitUndoActions(id);

	return true;
}

bool SharedCache::LoadImageWithInstallName(std::string installName)
{
	auto settings = m_dscView->GetLoadSettings(VIEW_NAME);

	std::unique_lock<std::mutex> lock(viewSpecificMutexes[m_dscView->GetFile()->GetSessionId()].viewOperationsThatInfluenceMetadataMutex);

	DeserializeFromRawView();
	m_logger->LogInfo("Loading image %s", installName.c_str());

	auto vm = GetVMMap();
	CacheImage* targetImage = nullptr;

	for (auto& cacheImage : m_images)
	{
		if (cacheImage.installName == installName)
		{
			targetImage = &cacheImage;
			break;
		}
	}

	auto header = m_headers[targetImage->headerLocation];

	auto id = m_dscView->BeginUndoActions();
	m_viewState = DSCViewStateLoadedWithImages;

	auto reader = VMReader(vm);
	reader.Seek(targetImage->headerLocation);

	std::vector<MemoryRegion*> regionsToLoad;

	for (auto& region : targetImage->regions)
	{
		bool allowLoadingLinkedit = false;
		if (settings && settings->Contains("loader.dsc.allowLoadingLinkeditSegments"))
			allowLoadingLinkedit = settings->Get<bool>("loader.dsc.allowLoadingLinkeditSegments", m_dscView);
		if ((region.prettyName.find("__LINKEDIT") != std::string::npos) && !allowLoadingLinkedit)
			continue;

		if (region.loaded)
		{
			m_logger->LogDebug("Skipping region %s as it is already loaded.", region.prettyName.c_str());
			continue;
		}

		auto targetFile = vm->MappingAtAddress(region.start).first.fileAccessor->lock();
		ParseAndApplySlideInfoForFile(targetFile);

		auto rawViewEnd = m_dscView->GetParentView()->GetEnd();

		auto buff = reader.ReadBuffer(region.start, region.size);
		m_dscView->GetParentView()->GetParentView()->WriteBuffer(rawViewEnd, buff);
		m_dscView->GetParentView()->WriteBuffer(rawViewEnd, buff);

		region.loaded = true;
		region.rawViewOffsetIfLoaded = rawViewEnd;

		m_regionsMappedIntoMemory.push_back(region);

		m_dscView->GetParentView()->AddAutoSegment(rawViewEnd, region.size, rawViewEnd, region.size, region.flags);
		m_dscView->AddUserSegment(region.start, region.size, rawViewEnd, region.size, region.flags);
		m_dscView->WriteBuffer(region.start, buff);

		regionsToLoad.push_back(&region);
	}

	if (regionsToLoad.empty())
	{
		m_logger->LogWarn("No regions to load for image %s", installName.c_str());
		return false;
	}

	std::unique_lock<std::mutex> typelibLock(viewSpecificMutexes[m_dscView->GetFile()->GetSessionId()].typeLibraryLookupAndApplicationMutex);
	auto typeLib = m_dscView->GetTypeLibrary(header.installName);

	if (!typeLib)
	{
		auto typeLibs = m_dscView->GetDefaultPlatform()->GetTypeLibrariesByName(header.installName);
		if (!typeLibs.empty())
		{
			typeLib = typeLibs[0];
			m_dscView->AddTypeLibrary(typeLib);
			m_logger->LogInfo("shared-cache: adding type library for '%s': %s (%s)",
				targetImage->installName.c_str(), typeLib->GetName().c_str(), typeLib->GetGuid().c_str());
		}
	}
	typelibLock.unlock();

	SaveToDSCView();

	auto h = SharedCache::LoadHeaderForAddress(vm, targetImage->headerLocation, installName);
	if (!h.has_value())
	{
		return false;
	}

	std::vector<MemoryRegion*> regions;
	for (auto& region : regionsToLoad)
	{
		regions.push_back(region);
	}

	SharedCache::InitializeHeader(m_dscView, vm.get(), *h, regions);

	try
	{
		auto objc = std::make_unique<DSCObjC::DSCObjCProcessor>(m_dscView, this, false);

		bool processCFStrings = true;
		bool processObjCMetadata = true;
		if (settings && settings->Contains("loader.dsc.processCFStrings"))
			processCFStrings = settings->Get<bool>("loader.dsc.processCFStrings", m_dscView);
		if (settings && settings->Contains("loader.dsc.processObjC"))
			processObjCMetadata = settings->Get<bool>("loader.dsc.processObjC", m_dscView);
		if (processObjCMetadata)
			objc->ProcessObjCData(vm, h->identifierPrefix);
		if (processCFStrings)
			objc->ProcessCFStrings(vm, h->identifierPrefix);
	}
	catch (const std::exception& ex)
	{
		m_logger->LogWarn("Error processing ObjC data: %s", ex.what());
	}
	catch (...)
	{
		m_logger->LogWarn("Error processing ObjC data");
	}

	m_dscView->AddAnalysisOption("linearsweep");
	m_dscView->UpdateAnalysis();

	m_dscView->CommitUndoActions(id);

	return true;
}

std::optional<SharedCacheMachOHeader> SharedCache::LoadHeaderForAddress(std::shared_ptr<VM> vm, uint64_t address, std::string installName)
{
	SharedCacheMachOHeader header;

	header.textBase = address;
	header.installName = installName;
	header.identifierPrefix = base_name(installName);

	std::string errorMsg;
	// address is a Raw file offset
	VMReader reader(vm);
	reader.Seek(address);

	header.ident.magic = reader.Read32();

	BNEndianness endianness;
	if (header.ident.magic == MH_MAGIC || header.ident.magic == MH_MAGIC_64)
		endianness = LittleEndian;
	else if (header.ident.magic == MH_CIGAM || header.ident.magic == MH_CIGAM_64)
		endianness = BigEndian;
	else
	{
		return {};
	}

	reader.SetEndianness(endianness);
	header.ident.cputype = reader.Read32();
	header.ident.cpusubtype = reader.Read32();
	header.ident.filetype = reader.Read32();
	header.ident.ncmds = reader.Read32();
	header.ident.sizeofcmds = reader.Read32();
	header.ident.flags = reader.Read32();
	if ((header.ident.cputype & MachOABIMask) == MachOABI64)  // address size == 8
	{
		header.ident.reserved = reader.Read32();
	}
	header.loadCommandOffset = reader.GetOffset();

	bool first = true;
	// Parse segment commands
	try
	{
		for (size_t i = 0; i < header.ident.ncmds; i++)
		{
			// BNLogInfo("of 0x%llx", reader.GetOffset());
			load_command load;
			segment_command_64 segment64;
			section_64 sect;
			memset(&sect, 0, sizeof(sect));
			size_t curOffset = reader.GetOffset();
			load.cmd = reader.Read32();
			load.cmdsize = reader.Read32();
			size_t nextOffset = curOffset + load.cmdsize;
			if (load.cmdsize < sizeof(load_command))
				return {};

			switch (load.cmd)
			{
			case LC_MAIN:
			{
				uint64_t entryPoint = reader.Read64();
				header.entryPoints.push_back({entryPoint, true});
				(void)reader.Read64();	// Stack start
				break;
			}
			case LC_SEGMENT:  // map the 32bit version to 64 bits
				segment64.cmd = LC_SEGMENT_64;
				reader.Read(&segment64.segname, 16);
				segment64.vmaddr = reader.Read32();
				segment64.vmsize = reader.Read32();
				segment64.fileoff = reader.Read32();
				segment64.filesize = reader.Read32();
				segment64.maxprot = reader.Read32();
				segment64.initprot = reader.Read32();
				segment64.nsects = reader.Read32();
				segment64.flags = reader.Read32();
				if (first)
				{
					if (!((header.ident.flags & MH_SPLIT_SEGS) || header.ident.cputype == MACHO_CPU_TYPE_X86_64)
						|| (segment64.flags & MACHO_VM_PROT_WRITE))
					{
						header.relocationBase = segment64.vmaddr;
						first = false;
					}
				}
				for (size_t j = 0; j < segment64.nsects; j++)
				{
					reader.Read(&sect.sectname, 16);
					reader.Read(&sect.segname, 16);
					sect.addr = reader.Read32();
					sect.size = reader.Read32();
					sect.offset = reader.Read32();
					sect.align = reader.Read32();
					sect.reloff = reader.Read32();
					sect.nreloc = reader.Read32();
					sect.flags = reader.Read32();
					sect.reserved1 = reader.Read32();
					sect.reserved2 = reader.Read32();
					// if the segment isn't mapped into virtual memory don't add the corresponding sections.
					if (segment64.vmsize > 0)
					{
						header.sections.push_back(sect);
					}
					if (!strncmp(sect.sectname, "__mod_init_func", 15))
						header.moduleInitSections.push_back(sect);
					if ((sect.flags & (S_ATTR_SELF_MODIFYING_CODE | S_SYMBOL_STUBS))
						== (S_ATTR_SELF_MODIFYING_CODE | S_SYMBOL_STUBS))
						header.symbolStubSections.push_back(sect);
					if ((sect.flags & S_NON_LAZY_SYMBOL_POINTERS) == S_NON_LAZY_SYMBOL_POINTERS)
						header.symbolPointerSections.push_back(sect);
					if ((sect.flags & S_LAZY_SYMBOL_POINTERS) == S_LAZY_SYMBOL_POINTERS)
						header.symbolPointerSections.push_back(sect);
				}
				header.segments.push_back(segment64);
				break;
			case LC_SEGMENT_64:
				segment64.cmd = LC_SEGMENT_64;
				reader.Read(&segment64.segname, 16);
				segment64.vmaddr = reader.Read64();
				segment64.vmsize = reader.Read64();
				segment64.fileoff = reader.Read64();
				segment64.filesize = reader.Read64();
				segment64.maxprot = reader.Read32();
				segment64.initprot = reader.Read32();
				segment64.nsects = reader.Read32();
				segment64.flags = reader.Read32();
				if (strncmp(segment64.segname, "__LINKEDIT", 10) == 0)
				{
					header.linkeditSegment = segment64;
					header.linkeditPresent = true;
				}
				if (first)
				{
					if (!((header.ident.flags & MH_SPLIT_SEGS) || header.ident.cputype == MACHO_CPU_TYPE_X86_64)
						|| (segment64.flags & MACHO_VM_PROT_WRITE))
					{
						header.relocationBase = segment64.vmaddr;
						first = false;
					}
				}
				for (size_t j = 0; j < segment64.nsects; j++)
				{
					reader.Read(&sect.sectname, 16);
					reader.Read(&sect.segname, 16);
					sect.addr = reader.Read64();
					sect.size = reader.Read64();
					sect.offset = reader.Read32();
					sect.align = reader.Read32();
					sect.reloff = reader.Read32();
					sect.nreloc = reader.Read32();
					sect.flags = reader.Read32();
					sect.reserved1 = reader.Read32();
					sect.reserved2 = reader.Read32();
					sect.reserved3 = reader.Read32();
					// if the segment isn't mapped into virtual memory don't add the corresponding sections.
					if (segment64.vmsize > 0)
					{
						header.sections.push_back(sect);
					}

					if (!strncmp(sect.sectname, "__mod_init_func", 15))
						header.moduleInitSections.push_back(sect);
					if ((sect.flags & (S_ATTR_SELF_MODIFYING_CODE | S_SYMBOL_STUBS))
						== (S_ATTR_SELF_MODIFYING_CODE | S_SYMBOL_STUBS))
						header.symbolStubSections.push_back(sect);
					if ((sect.flags & S_NON_LAZY_SYMBOL_POINTERS) == S_NON_LAZY_SYMBOL_POINTERS)
						header.symbolPointerSections.push_back(sect);
					if ((sect.flags & S_LAZY_SYMBOL_POINTERS) == S_LAZY_SYMBOL_POINTERS)
						header.symbolPointerSections.push_back(sect);
				}
				header.segments.push_back(segment64);
				break;
			case LC_ROUTINES:  // map the 32bit version to 64bits
				header.routines64.cmd = LC_ROUTINES_64;
				header.routines64.init_address = reader.Read32();
				header.routines64.init_module = reader.Read32();
				header.routines64.reserved1 = reader.Read32();
				header.routines64.reserved2 = reader.Read32();
				header.routines64.reserved3 = reader.Read32();
				header.routines64.reserved4 = reader.Read32();
				header.routines64.reserved5 = reader.Read32();
				header.routines64.reserved6 = reader.Read32();
				header.routinesPresent = true;
				break;
			case LC_ROUTINES_64:
				header.routines64.cmd = LC_ROUTINES_64;
				header.routines64.init_address = reader.Read64();
				header.routines64.init_module = reader.Read64();
				header.routines64.reserved1 = reader.Read64();
				header.routines64.reserved2 = reader.Read64();
				header.routines64.reserved3 = reader.Read64();
				header.routines64.reserved4 = reader.Read64();
				header.routines64.reserved5 = reader.Read64();
				header.routines64.reserved6 = reader.Read64();
				header.routinesPresent = true;
				break;
			case LC_FUNCTION_STARTS:
				header.functionStarts.funcoff = reader.Read32();
				header.functionStarts.funcsize = reader.Read32();
				header.functionStartsPresent = true;
				break;
			case LC_SYMTAB:
				header.symtab.symoff = reader.Read32();
				header.symtab.nsyms = reader.Read32();
				header.symtab.stroff = reader.Read32();
				header.symtab.strsize = reader.Read32();
				break;
			case LC_DYSYMTAB:
				header.dysymtab.ilocalsym = reader.Read32();
				header.dysymtab.nlocalsym = reader.Read32();
				header.dysymtab.iextdefsym = reader.Read32();
				header.dysymtab.nextdefsym = reader.Read32();
				header.dysymtab.iundefsym = reader.Read32();
				header.dysymtab.nundefsym = reader.Read32();
				header.dysymtab.tocoff = reader.Read32();
				header.dysymtab.ntoc = reader.Read32();
				header.dysymtab.modtaboff = reader.Read32();
				header.dysymtab.nmodtab = reader.Read32();
				header.dysymtab.extrefsymoff = reader.Read32();
				header.dysymtab.nextrefsyms = reader.Read32();
				header.dysymtab.indirectsymoff = reader.Read32();
				header.dysymtab.nindirectsyms = reader.Read32();
				header.dysymtab.extreloff = reader.Read32();
				header.dysymtab.nextrel = reader.Read32();
				header.dysymtab.locreloff = reader.Read32();
				header.dysymtab.nlocrel = reader.Read32();
				header.dysymPresent = true;
				break;
			case LC_DYLD_CHAINED_FIXUPS:
				header.chainedFixups.dataoff = reader.Read32();
				header.chainedFixups.datasize = reader.Read32();
				header.chainedFixupsPresent = true;
				break;
			case LC_DYLD_INFO:
			case LC_DYLD_INFO_ONLY:
				header.dyldInfo.rebase_off = reader.Read32();
				header.dyldInfo.rebase_size = reader.Read32();
				header.dyldInfo.bind_off = reader.Read32();
				header.dyldInfo.bind_size = reader.Read32();
				header.dyldInfo.weak_bind_off = reader.Read32();
				header.dyldInfo.weak_bind_size = reader.Read32();
				header.dyldInfo.lazy_bind_off = reader.Read32();
				header.dyldInfo.lazy_bind_size = reader.Read32();
				header.dyldInfo.export_off = reader.Read32();
				header.dyldInfo.export_size = reader.Read32();
				header.exportTrie.dataoff = header.dyldInfo.export_off;
				header.exportTrie.datasize = header.dyldInfo.export_size;
				header.exportTriePresent = true;
				header.dyldInfoPresent = true;
				break;
			case LC_DYLD_EXPORTS_TRIE:
				header.exportTrie.dataoff = reader.Read32();
				header.exportTrie.datasize = reader.Read32();
				header.exportTriePresent = true;
				break;
			case LC_THREAD:
			case LC_UNIXTHREAD:
				/*while (reader.GetOffset() < nextOffset)
				{

					thread_command thread;
					thread.flavor = reader.Read32();
					thread.count = reader.Read32();
					switch (m_archId)
					{
						case MachOx64:
							m_logger->LogDebug("x86_64 Thread state\n");
							if (thread.flavor != X86_THREAD_STATE64)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							//This wont be big endian so we can just read the whole thing
							reader.Read(&thread.statex64, sizeof(thread.statex64));
							header.entryPoints.push_back({thread.statex64.rip, false});
							break;
						case MachOx86:
							m_logger->LogDebug("x86 Thread state\n");
							if (thread.flavor != X86_THREAD_STATE32)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							//This wont be big endian so we can just read the whole thing
							reader.Read(&thread.statex86, sizeof(thread.statex86));
							header.entryPoints.push_back({thread.statex86.eip, false});
							break;
						case MachOArm:
							m_logger->LogDebug("Arm Thread state\n");
							if (thread.flavor != _ARM_THREAD_STATE)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							//This wont be big endian so we can just read the whole thing
							reader.Read(&thread.statearmv7, sizeof(thread.statearmv7));
							header.entryPoints.push_back({thread.statearmv7.r15, false});
							break;
						case MachOAarch64:
						case MachOAarch6432:
							m_logger->LogDebug("Aarch64 Thread state\n");
							if (thread.flavor != _ARM_THREAD_STATE64)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							reader.Read(&thread.stateaarch64, sizeof(thread.stateaarch64));
							header.entryPoints.push_back({thread.stateaarch64.pc, false});
							break;
						case MachOPPC:
							m_logger->LogDebug("PPC Thread state\n");
							if (thread.flavor != PPC_THREAD_STATE)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							//Read individual entries for endian reasons
							header.entryPoints.push_back({reader.Read32(), false});
							(void)reader.Read32();
							(void)reader.Read32();
							//Read the rest of the structure
							(void)reader.Read(&thread.stateppc.r1, sizeof(thread.stateppc) - (3 * 4));
							break;
						case MachOPPC64:
							m_logger->LogDebug("PPC64 Thread state\n");
							if (thread.flavor != PPC_THREAD_STATE64)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							header.entryPoints.push_back({reader.Read64(), false});
							(void)reader.Read64();
							(void)reader.Read64(); // Stack start
							(void)reader.Read(&thread.stateppc64.r1, sizeof(thread.stateppc64) - (3 * 8));
							break;
						default:
							m_logger->LogError("Unknown archid: %x", m_archId);
					}

				}*/
				break;
			case LC_LOAD_DYLIB:
			{
				uint32_t offset = reader.Read32();
				if (offset < nextOffset)
				{
					reader.Seek(curOffset + offset);
					std::string libname = reader.ReadCString(reader.GetOffset());
					header.dylibs.push_back(libname);
				}
			}
			break;
			case LC_BUILD_VERSION:
			{
				// m_logger->LogDebug("LC_BUILD_VERSION:");
				header.buildVersion.platform = reader.Read32();
				header.buildVersion.minos = reader.Read32();
				header.buildVersion.sdk = reader.Read32();
				header.buildVersion.ntools = reader.Read32();
				// m_logger->LogDebug("Platform: %s", BuildPlatformToString(header.buildVersion.platform).c_str());
				// m_logger->LogDebug("MinOS: %s", BuildToolVersionToString(header.buildVersion.minos).c_str());
				// m_logger->LogDebug("SDK: %s", BuildToolVersionToString(header.buildVersion.sdk).c_str());
				for (uint32_t j = 0; (i < header.buildVersion.ntools) && (j < 10); j++)
				{
					uint32_t tool = reader.Read32();
					uint32_t version = reader.Read32();
					header.buildToolVersions.push_back({tool, version});
					// m_logger->LogDebug("Build Tool: %s: %s", BuildToolToString(tool).c_str(),
					// BuildToolVersionToString(version).c_str());
				}
				break;
			}
			case LC_FILESET_ENTRY:
			{
				throw ReadException();
			}
			default:
				// m_logger->LogDebug("Unhandled command: %s : %" PRIu32 "\n", CommandToString(load.cmd).c_str(),
				// load.cmdsize);
				break;
			}
			if (reader.GetOffset() != nextOffset)
			{
				// m_logger->LogDebug("Didn't parse load command: %s fully %" PRIx64 ":%" PRIxPTR,
				// CommandToString(load.cmd).c_str(), reader.GetOffset(), nextOffset);
			}
			reader.Seek(nextOffset);
		}

		for (auto& section : header.sections)
		{
			char sectionName[17];
			memcpy(sectionName, section.sectname, sizeof(section.sectname));
			sectionName[16] = 0;
			if (header.identifierPrefix.empty())
				header.sectionNames.push_back(sectionName);
			else
				header.sectionNames.push_back(header.identifierPrefix + "::" + sectionName);
		}
	}
	catch (ReadException&)
	{
		return {};
	}

	return header;
}

void SharedCache::InitializeHeader(
	Ref<BinaryView> view, VM* vm, SharedCacheMachOHeader header, std::vector<MemoryRegion*> regionsToLoad)
{

	Ref<Settings> settings = view->GetLoadSettings(VIEW_NAME);
	bool applyFunctionStarts = true;
	if (settings && settings->Contains("loader.dsc.processFunctionStarts"))
		applyFunctionStarts = settings->Get<bool>("loader.dsc.processFunctionStarts", view);

	for (size_t i = 0; i < header.sections.size(); i++)
	{
		bool skip = false;
		for (const auto& region : regionsToLoad)
		{
			if (header.sections[i].addr >= region->start && header.sections[i].addr < region->start + region->size)
			{
				if (region->headerInitialized)
				{
					skip = true;
				}
				break;
			}
		}
		if (!header.sections[i].size || skip)
			continue;

		std::string type;
		BNSectionSemantics semantics = DefaultSectionSemantics;
		switch (header.sections[i].flags & 0xff)
		{
		case S_REGULAR:
			if (header.sections[i].flags & S_ATTR_PURE_INSTRUCTIONS)
			{
				type = "PURE_CODE";
				semantics = ReadOnlyCodeSectionSemantics;
			}
			else if (header.sections[i].flags & S_ATTR_SOME_INSTRUCTIONS)
			{
				type = "CODE";
				semantics = ReadOnlyCodeSectionSemantics;
			}
			else
			{
				type = "REGULAR";
			}
			break;
		case S_ZEROFILL:
			type = "ZEROFILL";
			semantics = ReadWriteDataSectionSemantics;
			break;
		case S_CSTRING_LITERALS:
			type = "CSTRING_LITERALS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_4BYTE_LITERALS:
			type = "4BYTE_LITERALS";
			break;
		case S_8BYTE_LITERALS:
			type = "8BYTE_LITERALS";
			break;
		case S_LITERAL_POINTERS:
			type = "LITERAL_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_NON_LAZY_SYMBOL_POINTERS:
			type = "NON_LAZY_SYMBOL_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_LAZY_SYMBOL_POINTERS:
			type = "LAZY_SYMBOL_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_SYMBOL_STUBS:
			type = "SYMBOL_STUBS";
			semantics = ReadOnlyCodeSectionSemantics;
			break;
		case S_MOD_INIT_FUNC_POINTERS:
			type = "MOD_INIT_FUNC_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_MOD_TERM_FUNC_POINTERS:
			type = "MOD_TERM_FUNC_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_COALESCED:
			type = "COALESCED";
			break;
		case S_GB_ZEROFILL:
			type = "GB_ZEROFILL";
			semantics = ReadWriteDataSectionSemantics;
			break;
		case S_INTERPOSING:
			type = "INTERPOSING";
			break;
		case S_16BYTE_LITERALS:
			type = "16BYTE_LITERALS";
			break;
		case S_DTRACE_DOF:
			type = "DTRACE_DOF";
			break;
		case S_LAZY_DYLIB_SYMBOL_POINTERS:
			type = "LAZY_DYLIB_SYMBOL_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_THREAD_LOCAL_REGULAR:
			type = "THREAD_LOCAL_REGULAR";
			break;
		case S_THREAD_LOCAL_ZEROFILL:
			type = "THREAD_LOCAL_ZEROFILL";
			break;
		case S_THREAD_LOCAL_VARIABLES:
			type = "THREAD_LOCAL_VARIABLES";
			break;
		case S_THREAD_LOCAL_VARIABLE_POINTERS:
			type = "THREAD_LOCAL_VARIABLE_POINTERS";
			break;
		case S_THREAD_LOCAL_INIT_FUNCTION_POINTERS:
			type = "THREAD_LOCAL_INIT_FUNCTION_POINTERS";
			break;
		default:
			type = "UNKNOWN";
			break;
		}
		if (i >= header.sectionNames.size())
			break;
		if (strncmp(header.sections[i].sectname, "__text", sizeof(header.sections[i].sectname)) == 0)
			semantics = ReadOnlyCodeSectionSemantics;
		if (strncmp(header.sections[i].sectname, "__const", sizeof(header.sections[i].sectname)) == 0)
			semantics = ReadOnlyDataSectionSemantics;
		if (strncmp(header.sections[i].sectname, "__data", sizeof(header.sections[i].sectname)) == 0)
			semantics = ReadWriteDataSectionSemantics;
		if (strncmp(header.sections[i].segname, "__DATA_CONST", sizeof(header.sections[i].segname)) == 0)
			semantics = ReadOnlyDataSectionSemantics;

		view->AddUserSection(header.sectionNames[i], header.sections[i].addr, header.sections[i].size, semantics,
			type, header.sections[i].align);
	}

	auto typeLib = view->GetTypeLibrary(header.installName);

	BinaryReader virtualReader(view);

	bool applyHeaderTypes = false;
	for (const auto& region : regionsToLoad)
	{
		if (header.textBase >= region->start && header.textBase < region->start + region->size)
		{
			if (!region->headerInitialized)
				applyHeaderTypes = true;
			break;
		}
	}
	if (applyHeaderTypes)
	{
		view->DefineDataVariable(header.textBase, Type::NamedType(view, QualifiedName("mach_header_64")));
		view->DefineAutoSymbol(
			new Symbol(DataSymbol, "__macho_header::" + header.identifierPrefix, header.textBase, LocalBinding));

		try
		{
			virtualReader.Seek(header.textBase + sizeof(mach_header_64));
			size_t sectionNum = 0;
			for (size_t i = 0; i < header.ident.ncmds; i++)
			{
				load_command load;
				uint64_t curOffset = virtualReader.GetOffset();
				load.cmd = virtualReader.Read32();
				load.cmdsize = virtualReader.Read32();
				uint64_t nextOffset = curOffset + load.cmdsize;
				switch (load.cmd)
				{
				case LC_SEGMENT:
				{
					view->DefineDataVariable(curOffset, Type::NamedType(view, QualifiedName("segment_command")));
					virtualReader.SeekRelative(5 * 8);
					size_t numSections = virtualReader.Read32();
					virtualReader.SeekRelative(4);
					for (size_t j = 0; j < numSections; j++)
					{
						view->DefineDataVariable(
							virtualReader.GetOffset(), Type::NamedType(view, QualifiedName("section")));
						view->DefineUserSymbol(new Symbol(DataSymbol,
							"__macho_section::" + header.identifierPrefix + "_[" + std::to_string(sectionNum++) + "]",
							virtualReader.GetOffset(), LocalBinding));
						virtualReader.SeekRelative((8 * 8) + 4);
					}
					break;
				}
				case LC_SEGMENT_64:
				{
					view->DefineDataVariable(curOffset, Type::NamedType(view, QualifiedName("segment_command_64")));
					virtualReader.SeekRelative(7 * 8);
					size_t numSections = virtualReader.Read32();
					virtualReader.SeekRelative(4);
					for (size_t j = 0; j < numSections; j++)
					{
						view->DefineDataVariable(
							virtualReader.GetOffset(), Type::NamedType(view, QualifiedName("section_64")));
						view->DefineUserSymbol(new Symbol(DataSymbol,
							"__macho_section_64::" + header.identifierPrefix + "_[" + std::to_string(sectionNum++) + "]",
							virtualReader.GetOffset(), LocalBinding));
						virtualReader.SeekRelative(10 * 8);
					}
					break;
				}
				case LC_SYMTAB:
					view->DefineDataVariable(curOffset, Type::NamedType(view, QualifiedName("symtab")));
					break;
				case LC_DYSYMTAB:
					view->DefineDataVariable(curOffset, Type::NamedType(view, QualifiedName("dysymtab")));
					break;
				case LC_UUID:
					view->DefineDataVariable(curOffset, Type::NamedType(view, QualifiedName("uuid")));
					break;
				case LC_ID_DYLIB:
				case LC_LOAD_DYLIB:
				case LC_REEXPORT_DYLIB:
				case LC_LOAD_WEAK_DYLIB:
				case LC_LOAD_UPWARD_DYLIB:
					view->DefineDataVariable(curOffset, Type::NamedType(view, QualifiedName("dylib_command")));
					if (load.cmdsize - 24 <= 150)
						view->DefineDataVariable(
							curOffset + 24, Type::ArrayType(Type::IntegerType(1, true), load.cmdsize - 24));
					break;
				case LC_CODE_SIGNATURE:
				case LC_SEGMENT_SPLIT_INFO:
				case LC_FUNCTION_STARTS:
				case LC_DATA_IN_CODE:
				case LC_DYLIB_CODE_SIGN_DRS:
				case LC_DYLD_EXPORTS_TRIE:
				case LC_DYLD_CHAINED_FIXUPS:
					view->DefineDataVariable(curOffset, Type::NamedType(view, QualifiedName("linkedit_data")));
					break;
				case LC_ENCRYPTION_INFO:
					view->DefineDataVariable(curOffset, Type::NamedType(view, QualifiedName("encryption_info")));
					break;
				case LC_VERSION_MIN_MACOSX:
				case LC_VERSION_MIN_IPHONEOS:
					view->DefineDataVariable(curOffset, Type::NamedType(view, QualifiedName("version_min")));
					break;
				case LC_DYLD_INFO:
				case LC_DYLD_INFO_ONLY:
					view->DefineDataVariable(curOffset, Type::NamedType(view, QualifiedName("dyld_info")));
					break;
				default:
					view->DefineDataVariable(curOffset, Type::NamedType(view, QualifiedName("load_command")));
					break;
				}

				view->DefineAutoSymbol(new Symbol(DataSymbol,
					"__macho_load_command::" + header.identifierPrefix + "_[" + std::to_string(i) + "]", curOffset,
					LocalBinding));
				virtualReader.Seek(nextOffset);
			}
		}
		catch (ReadException&)
		{
			LogError("Error when applying Mach-O header types at %" PRIx64, header.textBase);
		}
	}

	if (applyFunctionStarts && header.functionStartsPresent && header.linkeditPresent && vm->AddressIsMapped(header.linkeditSegment.vmaddr))
	{
		auto funcStarts =
			vm->MappingAtAddress(header.linkeditSegment.vmaddr)
				.first.fileAccessor->lock()
				->ReadBuffer(header.functionStarts.funcoff, header.functionStarts.funcsize);
		size_t i = 0;
		uint64_t curfunc = header.textBase;
		uint64_t curOffset;

		while (i < header.functionStarts.funcsize)
		{
			curOffset = readLEB128(funcStarts, header.functionStarts.funcsize, i);
			bool addFunction = false;
			for (const auto& region : regionsToLoad)
			{
				if (curfunc >= region->start && curfunc < region->start + region->size)
				{
					if (!region->headerInitialized)
						addFunction = true;
				}
			}
			// LogError("0x%llx, 0x%llx", header.textBase, curOffset);
			if (curOffset == 0 || !addFunction)
				continue;
			curfunc += curOffset;
			uint64_t target = curfunc;
			Ref<Platform> targetPlatform = view->GetDefaultPlatform();
			view->AddFunctionForAnalysis(targetPlatform, target);
		}
	}

	view->BeginBulkModifySymbols();
	if (header.symtab.symoff != 0 && header.linkeditPresent && vm->AddressIsMapped(header.linkeditSegment.vmaddr))
	{
		// Mach-O View symtab processing with
		// a ton of stuff cut out so it can work

		auto reader = vm->MappingAtAddress(header.linkeditSegment.vmaddr).first.fileAccessor->lock();
		// auto symtab = reader->ReadBuffer(header.symtab.symoff, header.symtab.nsyms * sizeof(nlist_64));
		auto strtab = reader->ReadBuffer(header.symtab.stroff, header.symtab.strsize);
		nlist_64 sym;
		memset(&sym, 0, sizeof(sym));
		auto N_TYPE = 0xE;	// idk
		std::vector<std::pair<uint64_t, std::pair<BNSymbolType, std::string>>> symbolInfos;
		for (size_t i = 0; i < header.symtab.nsyms; i++)
		{
			reader->Read(&sym, header.symtab.symoff + i * sizeof(nlist_64), sizeof(nlist_64));
			if (sym.n_strx >= header.symtab.strsize || ((sym.n_type & N_TYPE) == N_INDR))
				continue;

			std::string symbol((char*)strtab.GetDataAt(sym.n_strx));
			// BNLogError("%s: 0x%llx", symbol.c_str(), sym.n_value);
			if (symbol == "<redacted>")
				continue;

			BNSymbolType type = DataSymbol;
			uint32_t flags;
			if ((sym.n_type & N_TYPE) == N_SECT && sym.n_sect > 0 && (size_t)(sym.n_sect - 1) < header.sections.size())
			{}
			else if ((sym.n_type & N_TYPE) == N_ABS)
			{}
			else if ((sym.n_type & 0x1))
			{
				type = ExternalSymbol;
			}
			else
				continue;

			for (auto s : header.sections)
			{
				if (s.addr < sym.n_value)
				{
					if (s.addr + s.size > sym.n_value)
					{
						flags = s.flags;
					}
				}
			}

			if (type != ExternalSymbol)
			{
				if ((flags & S_ATTR_PURE_INSTRUCTIONS) == S_ATTR_PURE_INSTRUCTIONS
					|| (flags & S_ATTR_SOME_INSTRUCTIONS) == S_ATTR_SOME_INSTRUCTIONS)
					type = FunctionSymbol;
				else
					type = DataSymbol;
			}
			if ((sym.n_desc & N_ARM_THUMB_DEF) == N_ARM_THUMB_DEF)
				sym.n_value++;

			auto symbolObj = new Symbol(type, symbol, sym.n_value, GlobalBinding);
			if (type == FunctionSymbol)
			{
				Ref<Platform> targetPlatform = view->GetDefaultPlatform();
				view->AddFunctionForAnalysis(targetPlatform, sym.n_value);
			}
			if (typeLib)
			{
				auto _type = m_dscView->ImportTypeLibraryObject(typeLib, {symbolObj->GetFullName()});
				if (_type)
				{
					view->DefineAutoSymbolAndVariableOrFunction(view->GetDefaultPlatform(), symbolObj, _type);
				}
				else
					view->DefineAutoSymbol(symbolObj);
			}
			else
				view->DefineAutoSymbol(symbolObj);
			symbolInfos.push_back({sym.n_value, {type, symbol}});
		}
		m_symbolInfos[header.textBase] = symbolInfos;
	}

	if (header.exportTriePresent && header.linkeditPresent && vm->AddressIsMapped(header.linkeditSegment.vmaddr))
	{
		auto symbols = SharedCache::ParseExportTrie(vm->MappingAtAddress(header.linkeditSegment.vmaddr).first.fileAccessor->lock(), header);
		std::vector<std::pair<uint64_t, std::pair<BNSymbolType, std::string>>> exportMapping;
		for (const auto& symbol : symbols)
		{
			exportMapping.push_back({symbol->GetAddress(), {symbol->GetType(), symbol->GetRawName()}});
			if (typeLib)
			{
				auto type = m_dscView->ImportTypeLibraryObject(typeLib, {symbol->GetFullName()});

				if (type)
				{
					view->DefineAutoSymbolAndVariableOrFunction(view->GetDefaultPlatform(), symbol, type);
				}
				else
					view->DefineAutoSymbol(symbol);

				if (view->GetAnalysisFunction(view->GetDefaultPlatform(), symbol->GetAddress()))
				{
					auto func = view->GetAnalysisFunction(view->GetDefaultPlatform(), symbol->GetAddress());
					if (symbol->GetFullName() == "_objc_msgSend")
					{
						func->SetHasVariableArguments(false);
					}
					else if (symbol->GetFullName().find("_objc_retain_x") != std::string::npos || symbol->GetFullName().find("_objc_release_x") != std::string::npos)
					{
						auto x = symbol->GetFullName().rfind("x");
						auto num = symbol->GetFullName().substr(x + 1);

						std::vector<BinaryNinja::FunctionParameter> callTypeParams;
						auto cc = m_dscView->GetDefaultArchitecture()->GetCallingConventionByName("apple-arm64-objc-fast-arc-" + num);

						callTypeParams.push_back({"obj", m_dscView->GetTypeByName({ "id" }), true, BinaryNinja::Variable()});

						auto funcType = BinaryNinja::Type::FunctionType(m_dscView->GetTypeByName({ "id" }), cc, callTypeParams);
						func->SetUserType(funcType);
					}
				}
			}
			else
				view->DefineAutoSymbol(symbol);
		}
		m_exportInfos[header.textBase] = exportMapping;
	}
	view->EndBulkModifySymbols();

	for (auto region : regionsToLoad)
	{
		region->headerInitialized = true;
	}
}

struct ExportNode
{
	std::string text;
	uint64_t offset;
	uint64_t flags;
};


void SharedCache::ReadExportNode(std::vector<Ref<Symbol>>& symbolList, SharedCacheMachOHeader& header, DataBuffer& buffer, uint64_t textBase,
	const std::string& currentText, size_t cursor, uint32_t endGuard)
{

	if (cursor > endGuard)
		throw ReadException();

	uint64_t terminalSize = readValidULEB128(buffer, cursor);
	uint64_t childOffset = cursor + terminalSize;
	if (terminalSize != 0) {
		uint64_t imageOffset = 0;
		uint64_t flags = readValidULEB128(buffer, cursor);
		if (!(flags & EXPORT_SYMBOL_FLAGS_REEXPORT))
		{
			imageOffset = readValidULEB128(buffer, cursor);
			auto symbolType = m_dscView->GetAnalysisFunctionsForAddress(textBase + imageOffset).size() ? FunctionSymbol : DataSymbol;
			{
				if (!currentText.empty() && textBase + imageOffset)
				{
					uint32_t flags;
					BNSymbolType type;
					for (auto s : header.sections)
					{
						if (s.addr < textBase + imageOffset)
						{
							if (s.addr + s.size > textBase + imageOffset)
							{
								flags = s.flags;
							}
						}
					}
					if ((flags & S_ATTR_PURE_INSTRUCTIONS) == S_ATTR_PURE_INSTRUCTIONS
						|| (flags & S_ATTR_SOME_INSTRUCTIONS) == S_ATTR_SOME_INSTRUCTIONS)
						type = FunctionSymbol;
					else
						type = DataSymbol;

#if EXPORT_TRIE_DEBUG
						// BNLogInfo("export: %s -> 0x%llx", n.text.c_str(), image.baseAddress + n.offset);
#endif
					auto sym = new Symbol(type, currentText, textBase + imageOffset);
					symbolList.push_back(sym);
				}
			}
		}
	}
	cursor = childOffset;
	uint8_t childCount = buffer[cursor];
	cursor++;
	if (cursor > endGuard)
		throw ReadException();
	for (uint8_t i = 0; i < childCount; ++i)
	{
		std::string childText;
		while (buffer[cursor] != 0 & cursor <= endGuard)
			childText.push_back(buffer[cursor++]);
		cursor++;
		if (cursor > endGuard)
			throw ReadException();
		auto next = readValidULEB128(buffer, cursor);
		if (next == 0)
			throw ReadException();
		ReadExportNode(symbolList, header, buffer, textBase, currentText + childText, next, endGuard);
	}
}


std::vector<Ref<Symbol>> SharedCache::ParseExportTrie(std::shared_ptr<MMappedFileAccessor> linkeditFile, SharedCacheMachOHeader header)
{
	std::vector<Ref<Symbol>> symbols;
	try
	{
		auto reader = linkeditFile;

		std::vector<ExportNode> nodes;

		DataBuffer buffer = reader->ReadBuffer(header.exportTrie.dataoff, header.exportTrie.datasize);
		ReadExportNode(symbols, header, buffer, header.textBase, "", 0, header.exportTrie.datasize);
	}
	catch (std::exception& e)
	{
		BNLogError("Failed to load Export Trie");
	}
	return symbols;
}

std::vector<std::string> SharedCache::GetAvailableImages()
{
	std::vector<std::string> installNames;
	for (const auto& header : m_headers)
	{
		installNames.push_back(header.second.installName);
	}
	return installNames;
}


std::vector<std::pair<std::string, Ref<Symbol>>> SharedCache::LoadAllSymbolsAndWait()
{
	std::unique_lock<std::mutex> initialLoadBlock(viewSpecificMutexes[m_dscView->GetFile()->GetSessionId()].viewOperationsThatInfluenceMetadataMutex);

	std::vector<std::pair<std::string, Ref<Symbol>>> symbols;
	for (const auto& img : m_images)
	{
		auto header = HeaderForAddress(img.headerLocation);
		std::shared_ptr<MMappedFileAccessor> mapping;
		try {
			mapping = MMappedFileAccessor::Open(m_dscView, m_dscView->GetFile()->GetSessionId(), header->exportTriePath)->lock();
		}
		catch (...)
		{
			m_logger->LogWarn("Serious Error: Failed to open export trie %s for %s", header->exportTriePath.c_str(), header->installName.c_str());
			continue;
		}
		auto exportList = SharedCache::ParseExportTrie(mapping, *header);
		std::vector<std::pair<uint64_t, std::pair<BNSymbolType, std::string>>> exportMapping;
		for (const auto& sym : exportList)
		{
			exportMapping.push_back({sym->GetAddress(), {sym->GetType(), sym->GetRawName()}});
			symbols.push_back({img.installName, sym});
		}
		m_exportInfos[header->textBase] = exportMapping;
	}

	SaveToDSCView();

	return symbols;
}


std::string SharedCache::SerializedImageHeaderForAddress(uint64_t address)
{
	auto header = HeaderForAddress(address);
	if (header)
	{
		return header->AsString();
	}
	return "";
}


std::string SharedCache::SerializedImageHeaderForName(std::string name)
{
	auto header = HeaderForAddress(m_imageStarts[name]);
	if (header)
	{
		return header->AsString();
	}
	return "";
}


void SharedCache::FindSymbolAtAddrAndApplyToAddr(uint64_t symbolLocation, uint64_t targetLocation, bool triggerReanalysis)
{
	std::string prefix = "";
	if (symbolLocation != targetLocation)
		prefix = "j_";
	if (auto preexistingSymbol = m_dscView->GetSymbolByAddress(targetLocation))
	{
		if (preexistingSymbol->GetFullName().find("j_") != std::string::npos)
			return;
	}
	auto id = m_dscView->BeginUndoActions();
	if (auto loadedSymbol = m_dscView->GetSymbolByAddress(symbolLocation))
	{
		if (m_dscView->GetAnalysisFunction(m_dscView->GetDefaultPlatform(), targetLocation))
			m_dscView->DefineUserSymbol(new Symbol(FunctionSymbol, prefix + loadedSymbol->GetFullName(), targetLocation));
		else
			m_dscView->DefineUserSymbol(new Symbol(loadedSymbol->GetType(), prefix + loadedSymbol->GetFullName(), targetLocation));
	}
	else if (auto sym = m_dscView->GetSymbolByAddress(symbolLocation))
	{
		if (m_dscView->GetAnalysisFunction(m_dscView->GetDefaultPlatform(), targetLocation))
			m_dscView->DefineUserSymbol(new Symbol(FunctionSymbol, prefix + sym->GetFullName(), targetLocation));
		else
			m_dscView->DefineUserSymbol(new Symbol(sym->GetType(), prefix + sym->GetFullName(), targetLocation));
	}
	m_dscView->ForgetUndoActions(id);
	auto header = HeaderForAddress(symbolLocation);
	if (header)
	{
		std::shared_ptr<MMappedFileAccessor> mapping;
		try {
			mapping = MMappedFileAccessor::Open(m_dscView, m_dscView->GetFile()->GetSessionId(), header->exportTriePath)->lock();
		}
		catch (...)
		{
			m_logger->LogWarn("Serious Error: Failed to open export trie for %s", header->installName.c_str());
			return;
		}
		auto exportList = SharedCache::ParseExportTrie(mapping, *header);
		std::vector<std::pair<uint64_t, std::pair<BNSymbolType, std::string>>> exportMapping;
		std::unique_lock<std::mutex> lock(viewSpecificMutexes[m_dscView->GetFile()->GetSessionId()].typeLibraryLookupAndApplicationMutex);
		auto typeLib = m_dscView->GetTypeLibrary(header->installName);
		if (!typeLib)
		{
			auto typeLibs = m_dscView->GetDefaultPlatform()->GetTypeLibrariesByName(header->installName);
			if (!typeLibs.empty())
			{
				typeLib = typeLibs[0];
				m_dscView->AddTypeLibrary(typeLib);
			}
		}
		lock.unlock();
		id = m_dscView->BeginUndoActions();
		m_dscView->BeginBulkModifySymbols();
		for (const auto& sym : exportList)
		{
			exportMapping.push_back({sym->GetAddress(), {sym->GetType(), sym->GetRawName()}});
			if (sym->GetAddress() == symbolLocation)
			{
				if (auto func = m_dscView->GetAnalysisFunction(m_dscView->GetDefaultPlatform(), targetLocation))
				{
					m_dscView->DefineUserSymbol(
						new Symbol(FunctionSymbol, prefix + sym->GetFullName(), targetLocation));

					if (typeLib)
						if (auto type = m_dscView->ImportTypeLibraryObject(typeLib, {sym->GetFullName()}))
							func->SetUserType(type);
				}
				else
				{
					m_dscView->DefineUserSymbol(
						new Symbol(sym->GetType(), prefix + sym->GetFullName(), targetLocation));

					if (typeLib)
						if (auto type = m_dscView->ImportTypeLibraryObject(typeLib, {sym->GetFullName()}))
							m_dscView->DefineUserDataVariable(targetLocation, type);
				}
				if (triggerReanalysis)
				{
					auto func = m_dscView->GetAnalysisFunction(m_dscView->GetDefaultPlatform(), targetLocation);
					if (func)
						func->Reanalyze();
				}
				break;
			}
		}
		{
			std::unique_lock<std::mutex> _lock(viewSpecificMutexes[m_dscView->GetFile()->GetSessionId()].viewOperationsThatInfluenceMetadataMutex);
			m_exportInfos[header->textBase] = exportMapping;
		}
		m_dscView->EndBulkModifySymbols();
		m_dscView->ForgetUndoActions(id);
	}
}


bool SharedCache::SaveToDSCView()
{
	if (m_dscView)
	{
		auto data = AsMetadata();
		m_dscView->StoreMetadata(SharedCacheMetadataTag, data);
		m_dscView->GetParentView()->GetParentView()->StoreMetadata(SharedCacheMetadataTag, data);
		std::unique_lock<std::recursive_mutex> viewStateCacheLock(viewStateMutex);
		ViewStateCacheStore c;
		c.m_imageStarts = m_imageStarts;
		c.m_cacheFormat = m_cacheFormat;
		c.m_backingCaches = m_backingCaches;
		c.m_viewState = m_viewState;
		c.m_headers = m_headers;
		c.m_images = m_images;
		c.m_regionsMappedIntoMemory = m_regionsMappedIntoMemory;
		c.m_stubIslandRegions = m_stubIslandRegions;
		c.m_dyldDataRegions = m_dyldDataRegions;
		c.m_nonImageRegions = m_nonImageRegions;
		c.m_baseFilePath = m_baseFilePath;
		c.m_exportInfos = m_exportInfos;
		c.m_symbolInfos = m_symbolInfos;
		viewStateCache[m_dscView->GetFile()->GetSessionId()] = c;

		m_metadataValid = true;

		return true;
	}
	return false;
}
std::vector<MemoryRegion> SharedCache::GetMappedRegions() const
{
	std::unique_lock<std::mutex> lock(viewSpecificMutexes[m_dscView->GetFile()->GetSessionId()].viewOperationsThatInfluenceMetadataMutex);
	return m_regionsMappedIntoMemory;
}

extern "C"
{
	BNSharedCache* BNGetSharedCache(BNBinaryView* data)
	{
		if (!data)
			return nullptr;

		Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
		if (auto cache = SharedCache::GetFromDSCView(view))
		{
			cache->AddAPIRef();
			return cache->GetAPIObject();
		}

		return nullptr;
	}

	BNSharedCache* BNNewSharedCacheReference(BNSharedCache* cache)
	{
		if (!cache->object)
			return nullptr;

		cache->object->AddAPIRef();
		return cache;
	}

	void BNFreeSharedCacheReference(BNSharedCache* cache)
	{
		if (!cache->object)
			return;

		cache->object->ReleaseAPIRef();
	}

	bool BNDSCViewLoadImageWithInstallName(BNSharedCache* cache, char* name)
	{
		std::string imageName = std::string(name);
		// FIXME !!!!!!!! BNFreeString(name);

		if (cache->object)
			return cache->object->LoadImageWithInstallName(imageName);

		return false;
	}

	bool BNDSCViewLoadSectionAtAddress(BNSharedCache* cache, uint64_t addr)
	{
		if (cache->object)
		{
			return cache->object->LoadSectionAtAddress(addr);
		}

		return false;
	}

	bool BNDSCViewLoadImageContainingAddress(BNSharedCache* cache, uint64_t address)
	{
		if (cache->object)
		{
			return cache->object->LoadImageContainingAddress(address);
		}

		return false;
	}

	char** BNDSCViewGetInstallNames(BNSharedCache* cache, size_t* count)
	{
		if (cache->object)
		{
			auto value = cache->object->GetAvailableImages();
			*count = value.size();

			std::vector<const char*> cstrings;
			for (size_t i = 0; i < value.size(); i++)
			{
				cstrings.push_back(value[i].c_str());
			}
			return BNAllocStringList(cstrings.data(), cstrings.size());
		}
		*count = 0;
		return nullptr;
	}

	BNDSCSymbolRep* BNDSCViewLoadAllSymbolsAndWait(BNSharedCache* cache, size_t* count)
	{
		if (cache->object)
		{
			auto value = cache->object->LoadAllSymbolsAndWait();
			*count = value.size();

			BNDSCSymbolRep* symbols = (BNDSCSymbolRep*)malloc(sizeof(BNDSCSymbolRep) * value.size());
			for (size_t i = 0; i < value.size(); i++)
			{
				symbols[i].address = value[i].second->GetAddress();
				symbols[i].name = BNAllocString(value[i].second->GetRawName().c_str());
				symbols[i].image = BNAllocString(value[i].first.c_str());
			}
			return symbols;
		}
		*count = 0;
		return nullptr;
	}

	void BNDSCViewFreeSymbols(BNDSCSymbolRep* symbols, size_t count)
	{
		for (size_t i = 0; i < count; i++)
		{
			BNFreeString(symbols[i].name);
			BNFreeString(symbols[i].image);
		}
		delete symbols;
	}

	char* BNDSCViewGetNameForAddress(BNSharedCache* cache, uint64_t address)
	{
		if (cache->object)
		{
			return BNAllocString(cache->object->NameForAddress(address).c_str());
		}

		return nullptr;
	}

	char* BNDSCViewGetImageNameForAddress(BNSharedCache* cache, uint64_t address)
	{
		if (cache->object)
		{
			return BNAllocString(cache->object->ImageNameForAddress(address).c_str());
		}

		return nullptr;
	}

	uint64_t BNDSCViewLoadedImageCount(BNSharedCache* cache)
	{
		// FIXME?
		return 0;
	}

	BNDSCViewState BNDSCViewGetState(BNSharedCache* cache)
	{
		if (cache->object)
		{
			return (BNDSCViewState)cache->object->State();
		}

		return BNDSCViewState::Unloaded;
	}


	BNDSCMappedMemoryRegion* BNDSCViewGetLoadedRegions(BNSharedCache* cache, size_t* count)
	{
		if (cache->object)
		{
			auto regions = cache->object->GetMappedRegions();
			*count = regions.size();
			BNDSCMappedMemoryRegion* mappedRegions = (BNDSCMappedMemoryRegion*)malloc(sizeof(BNDSCMappedMemoryRegion) * regions.size());
			for (size_t i = 0; i < regions.size(); i++)
			{
				mappedRegions[i].vmAddress = regions[i].start;
				mappedRegions[i].size = regions[i].size;
				mappedRegions[i].name = BNAllocString(regions[i].prettyName.c_str());
			}
			return mappedRegions;
		}
		*count = 0;
		return nullptr;
	}

	void BNDSCViewFreeLoadedRegions(BNDSCMappedMemoryRegion* images, size_t count)
	{
		for (size_t i = 0; i < count; i++)
		{
			BNFreeString(images[i].name);
		}
		delete images;
	}


	BNDSCBackingCache* BNDSCViewGetBackingCaches(BNSharedCache* cache, size_t* count)
	{
		BNDSCBackingCache* caches = nullptr;

		if (cache->object)
		{
			auto viewCaches = cache->object->BackingCaches();
			*count = viewCaches.size();
			caches = (BNDSCBackingCache*)malloc(sizeof(BNDSCBackingCache) * viewCaches.size());
			for (size_t i = 0; i < viewCaches.size(); i++)
			{
				caches[i].path = BNAllocString(viewCaches[i].path.c_str());
				caches[i].isPrimary = viewCaches[i].isPrimary;

				BNDSCBackingCacheMapping* mappings;
				mappings = (BNDSCBackingCacheMapping*)malloc(sizeof(BNDSCBackingCacheMapping) * viewCaches[i].mappings.size());

				size_t j = 0;
				for (const auto& [fileOffset, mapping] : viewCaches[i].mappings)
				{
					mappings[j].vmAddress = mapping.first;
					mappings[j].size = mapping.second;
					mappings[j].fileOffset = fileOffset;
					j++;
				}
				caches[i].mappings = mappings;
				caches[i].mappingCount = viewCaches[i].mappings.size();
			}
		}

		return caches;
	}

	void BNDSCViewFreeBackingCaches(BNDSCBackingCache* caches, size_t count)
	{
		for (size_t i = 0; i < count; i++)
		{
			delete[] caches[i].mappings;
			BNFreeString(caches[i].path);
		}
		delete[] caches;
	}

	void BNDSCFindSymbolAtAddressAndApplyToAddress(BNSharedCache* cache, uint64_t symbolLocation, uint64_t targetLocation, bool triggerReanalysis)
	{
		if (cache->object)
		{
			cache->object->FindSymbolAtAddrAndApplyToAddr(symbolLocation, targetLocation, triggerReanalysis);
		}
	}

	BNDSCImage* BNDSCViewGetAllImages(BNSharedCache* cache, size_t* count)
	{
		if (cache->object)
		{
			auto vm = cache->object->GetVMMap(true);
			auto viewImageHeaders = cache->object->AllImageHeaders();
			*count = viewImageHeaders.size();
			BNDSCImage* images = (BNDSCImage*)malloc(sizeof(BNDSCImage) * viewImageHeaders.size());
			size_t i = 0;
			for (const auto& [baseAddress, header] : viewImageHeaders)
			{
				images[i].name = BNAllocString(header.installName.c_str());
				images[i].headerAddress = baseAddress;
				images[i].mappingCount = header.sections.size();
				images[i].mappings = (BNDSCImageMemoryMapping*)malloc(sizeof(BNDSCImageMemoryMapping) * header.sections.size());
				for (size_t j = 0; j < header.sections.size(); j++)
				{
					images[i].mappings[j].rawViewOffset = header.sections[j].offset;
					images[i].mappings[j].vmAddress = header.sections[j].addr;
					images[i].mappings[j].size = header.sections[j].size;
					images[i].mappings[j].name = BNAllocString(header.sectionNames[j].c_str());
					images[i].mappings[j].filePath = BNAllocString(vm->MappingAtAddress(header.sections[j].addr).first.filePath.c_str());
				}
				i++;
			}
			return images;
		}
		*count = 0;
		return nullptr;
	}

	void BNDSCViewFreeAllImages(BNDSCImage* images, size_t count)
	{
		for (size_t i = 0; i < count; i++)
		{
			for (size_t j = 0; j < images[i].mappingCount; j++)
			{
				BNFreeString(images[i].mappings[j].name);
				BNFreeString(images[i].mappings[j].filePath);
			}
			delete[] images[i].mappings;
			BNFreeString(images[i].name);
		}
		delete[] images;
	}

	char* BNDSCViewGetImageHeaderForAddress(BNSharedCache* cache, uint64_t address)
	{
		if (cache->object)
		{
			auto header = cache->object->SerializedImageHeaderForAddress(address);
			return BNAllocString(header.c_str());
		}

		return nullptr;
	}

	char* BNDSCViewGetImageHeaderForName(BNSharedCache* cache, char* name)
	{
		std::string imageName = std::string(name);
		BNFreeString(name);
		if (cache->object)
		{
			auto header = cache->object->SerializedImageHeaderForName(imageName);
			return BNAllocString(header.c_str());
		}

		return nullptr;
	}

	BNDSCMemoryUsageInfo BNDSCViewGetMemoryUsageInfo()
	{
		BNDSCMemoryUsageInfo info;
		info.mmapRefs = mmapCount.load();
		info.sharedCacheRefs = sharedCacheReferences.load();
		return info;
	}

	BNDSCViewLoadProgress BNDSCViewGetLoadProgress(uint64_t sessionID)
	{
		progressMutex.lock();
		if (progressMap.find(sessionID) == progressMap.end())
		{
			progressMutex.unlock();
			return LoadProgressNotStarted;
		}
		auto progress = progressMap[sessionID];
		progressMutex.unlock();
		return progress;
	}

	uint64_t BNDSCViewFastGetBackingCacheCount(BNBinaryView* data)
	{
		Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
		return SharedCache::FastGetBackingCacheCount(view);
	}
}

[[maybe_unused]] DSCViewType* g_dscViewType;
[[maybe_unused]] DSCRawViewType* g_dscRawViewType;

void InitDSCViewType()
{
	MMappedFileAccessor::InitialVMSetup();
	std::atexit(VMShutdown);

	static DSCRawViewType rawType;
	BinaryViewType::Register(&rawType);
	static DSCViewType type;
	BinaryViewType::Register(&type);
	g_dscViewType = &type;
	g_dscRawViewType = &rawType;
}
