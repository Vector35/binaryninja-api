#include "SharedCache.h"

#include <regex>
#include <filesystem>

#include "MachO.h"
#include "SlideInfo.h"

using namespace BinaryNinja;

// The next id to use when calling Cache::AddEntry
static CacheEntryId nextId = 1;

Ref<Symbol> CacheSymbol::ToBNSymbol(BinaryView& view) const
{
	QualifiedName qname;
	Ref<Type> outType;
	std::string shortName = name;
	if (DemangleGeneric(view.GetDefaultArchitecture(), name, outType, qname, &view, true))
		shortName = qname.GetString();
	return new Symbol(type, shortName, shortName, name, address, nullptr);
}

std::vector<std::string> CacheImage::GetDependencies() const
{
	if (header)
		return header->dylibs;
	return {};
}

CacheEntry::CacheEntry(std::string filePath, std::string fileName, CacheEntryType type, dyld_cache_header header,
	std::vector<dyld_cache_mapping_info> mappings, std::unordered_map<std::string, dyld_cache_image_info> images)
{
	m_filePath = std::move(filePath);
	m_fileName = std::move(fileName);
	m_type = type;
	m_header = header;
	m_mappings = std::move(mappings);
	m_images = std::move(images);
}

std::optional<CacheEntry> CacheEntry::FromFile(const std::string& filePath, const std::string& fileName, CacheEntryType type)
{
	auto file = FileAccessorCache::Global().Open(filePath).lock();

	// TODO: Pull this out into another function so we can do IsValidDSCFile or something.
	// We first want to make sure that the base file is dyld.
	// All entries must start with "dyld".
	DataBuffer sig = file->ReadBuffer(0, 4);
	if (sig.GetLength() != 4)
		return std::nullopt;
	const char* magic = (char*)sig.GetData();
	if (strncmp(magic, "dyld", 4) != 0)
		return std::nullopt;

	// Read the header, this _should_ be compatible with all known DSC formats.
	// Mason: the above is not true! https://github.com/Vector35/binaryninja-api/issues/6073
	dyld_cache_header header = {};
	file->Read(&header, 0, sizeof(header));

	// Read the mappings using the headers `mappingCount` and `mappingOffset`.
	dyld_cache_mapping_info currentMapping = {};
	std::vector<dyld_cache_mapping_info> mappings;
	for (size_t i = 0; i < header.mappingCount; i++)
	{
		file->Read(&currentMapping, header.mappingOffset + (i * sizeof(currentMapping)), sizeof(currentMapping));
		mappings.push_back(currentMapping);
	}

	// Handle special entry types.
	if (fileName.find(".dylddata") != std::string::npos)
	{
		// We found a single dyld data cache entry file. Mark it as such!
		type = CacheEntryType::DyldData;
	}
	else if (fileName.find(".symbols") != std::string::npos)
	{
		// We found a single symbols cache entry file. Mark it as such!
		type = CacheEntryType::Symbols;
	}
	else if (mappings.size() == 1 && header.imagesCountOld == 0 && header.imagesCount == 0
		&& header.imagesTextOffset == 0)
	{
		// Stub entry file, should only have a single mapping and no images.
		// NOTE: If we end up identifying something incorrectly as a stub we need to restrict this further.
		// We found a single stub cache entry file. Mark it as such!
		type = CacheEntryType::Stub;
	}

	// Gather all images for the entry.
	std::unordered_map<std::string, dyld_cache_image_info> images;
	dyld_cache_image_info currentImg {};
	for (size_t i = 0; i < header.imagesCount; i++)
	{
		file->Read(
			&currentImg, header.imagesOffset + (i * sizeof(dyld_cache_image_info)), sizeof(dyld_cache_image_info));
		auto imagePath = file->ReadNullTermString(currentImg.pathFileOffset);
		images.insert_or_assign(imagePath, currentImg);
	}

	// Handle old dyld format that uses old images field.
	for (size_t i = 0; i < header.imagesCountOld; i++)
	{
		file->Read(
			&currentImg, header.imagesOffsetOld + (i * sizeof(dyld_cache_image_info)), sizeof(dyld_cache_image_info));
		auto imagePath = file->ReadNullTermString(currentImg.pathFileOffset);
		images.insert_or_assign(imagePath, currentImg);
	}

	// NOTE: I am not sure how the header type has changed over time but if apple is replacing fields with other ones
	// NOTE: And branchPoolsCount is not zero for earlier shared caches (non split cache ones) than we need to check
	// this! Also make pseudo-image for the branch pools, so we can map them in to the binary view.
	for (size_t i = 0; i < header.branchPoolsCount; i++)
	{
		dyld_cache_image_info branchIslandImg = {};
		// TODO: uint64_t means this only works on 64bit... tbh tho this is fine this is a new addition so 32bit doesnt
		// apply here.
		// TODO: If we want to make this work for other addr sizes we need the binary view in this function.
		branchIslandImg.address = header.branchPoolsOffset + (i * sizeof(uint64_t));
		// Mason: why such a long name for the image???
		auto imageName = fmt::format("dyld_shared_cache_branch_islands_{}", i);
		images.insert_or_assign(imageName, branchIslandImg);
	}

	return CacheEntry(filePath, fileName, type, header, mappings, images);
}

WeakFileAccessor CacheEntry::GetAccessor() const
{
	return FileAccessorCache::Global().Open(m_filePath);
}

std::optional<uint64_t> CacheEntry::GetHeaderAddress() const
{
	// The mapping at file offset 0 will contain the header (duh).
	return GetMappedAddress(0);
}

std::optional<uint64_t> CacheEntry::GetMappedAddress(uint64_t fileOffset) const
{
	for (const auto& mapping : m_mappings)
		if (mapping.fileOffset <= fileOffset && mapping.fileOffset + mapping.size > fileOffset)
			return mapping.address + (fileOffset - mapping.fileOffset);
	return std::nullopt;
}

SharedCache::SharedCache(uint64_t addressSize)
{
	m_addressSize = addressSize;
	m_vm = std::make_shared<VirtualMemory>();
}


void SharedCache::AddImage(CacheImage image)
{
	m_images.insert({image.headerAddress, std::move(image)});
}

void SharedCache::AddRegion(CacheRegion region)
{
	// Handle overlapping regions here.
	const auto regionRange = region.AsAddressRange();
	// First region at or past the start of the region.
	const auto begin = m_regions.lower_bound(regionRange.start);
	if (begin == m_regions.end())
	{
		AddNonOverlappingRegion(std::move(region));
		return;
	}

	// First region past the end of the region.
	const auto end = m_regions.lower_bound(regionRange.end);

	for (auto it = begin; it != end; ++it)
	{
		const uint64_t newRegionSize = it->second.start - region.start;
		if (newRegionSize)
		{
			CacheRegion newRegion(region);
			newRegion.size = newRegionSize;
			AddNonOverlappingRegion(std::move(newRegion));
		}

		region.start = it->second.start + it->second.size;
		region.size -= (newRegionSize + it->second.size);
	}

	// Add remaining region.
	if (region.size > 0)
		AddNonOverlappingRegion(std::move(region));
}

bool SharedCache::AddNonOverlappingRegion(CacheRegion region)
{
	auto [_, inserted] = m_regions.insert(std::make_pair(region.AsAddressRange(), std::move(region)));
	return inserted;
}

void SharedCache::AddSymbol(CacheSymbol symbol)
{
	m_symbols.insert({symbol.address, std::move(symbol)});
}

void SharedCache::AddSymbols(std::vector<CacheSymbol>&& symbols)
{
	for (auto&& symbol : symbols)
		m_symbols.emplace(symbol.address, std::move(symbol));
}

CacheEntryId SharedCache::AddEntry(CacheEntry entry)
{
	// TODO: Maybe check to see if we already added the file?
	// TODO: I doubt we will ever accidentally call this for the same entry...
	// This is monotonically increasing so you can tell how many times we have called this function :)
	CacheEntryId id = nextId++;

	// Get the file accessor to associate with the virtual memory region.
	auto fileAccessor = FileAccessorCache::Global().Open(entry.GetFilePath());

	// Populate virtual memory using the entry mappings, by doing so we can now
	// read the memory of the mapped regions of the cache entry file.
	const auto& mappings = entry.GetMappings();
	for (const auto& mapping : mappings)
	{
		m_vm->MapRegion(fileAccessor, {mapping.address, mapping.address + mapping.size}, mapping.fileOffset);

		// Recalculate the base address.
		if (mapping.address < m_baseAddress || m_baseAddress == 0)
			m_baseAddress = mapping.address;
	}

	// We are done and can make the entry visible to the entire cache.
	m_entries.insert({id, std::move(entry)});
	return id;
}

bool SharedCache::ProcessEntryImage(const std::string& path, const dyld_cache_image_info& info)
{
	auto imageHeader = SharedCacheMachOHeader::ParseHeaderForAddress(m_vm, info.address, path);
	if (!imageHeader.has_value())
		return false;

	// Add the image to the cache.
	CacheImage image;
	image.headerAddress = info.address;
	image.path = path;

	// Add all image regions.
	for (const auto& segment : imageHeader->segments)
	{
		char segName[17];
		memcpy(segName, segment.segname, 16);
		segName[16] = 0;

		// Many images include a __LINKEDIT segment that share a single region in the shared cache.
		// Reuse the same `MemoryRegion` to represent all of these link edit regions.
		// Check to see if we have a shared region, if so skip it.
		if (std::string(segName) == "__LINKEDIT")
		{
			// TODO: Loosen this to any shared region?
			if (const auto linkEditRegion = GetRegionAt(segment.vmaddr))
			{
				image.regionStarts.push_back(linkEditRegion->start);
				continue;
			}
		}

		CacheRegion sectionRegion;
		sectionRegion.type = CacheRegionType::Image;
		sectionRegion.name = imageHeader->identifierPrefix + "::" + std::string(segName);
		sectionRegion.start = segment.vmaddr;
		sectionRegion.size = segment.vmsize;
		// Associate this region with this image, this makes it easier to identify what image owns this region.
		sectionRegion.imageStart = image.headerAddress;

		uint32_t flags = SegmentFlagsFromMachOProtections(segment.initprot, segment.maxprot);
		// if we're positive we have an entry point for some reason, force the segment
		// executable. this helps with kernel images.
		for (const auto& entryPoint : imageHeader->m_entryPoints)
			if (segment.vmaddr <= entryPoint && (entryPoint < (segment.vmaddr + segment.filesize)))
				flags |= SegmentExecutable;
		sectionRegion.flags = static_cast<BNSegmentFlag>(flags);

		// Add the image section to the cache and also to the image region starts
		AddRegion(sectionRegion);
		image.regionStarts.push_back(sectionRegion.start);
	}

	// Add the exported symbols to the available symbols.
	std::vector<CacheSymbol> exportSymbols = imageHeader->ReadExportSymbolTrie(*m_vm);
	AddSymbols(std::move(exportSymbols));

	// This is behind a shared pointer as the header itself is very large.
	// TODO: Make this a unique pointer? I think the image should own the header at this point?
	image.header = std::make_shared<SharedCacheMachOHeader>(*imageHeader);

	AddImage(std::move(image));
	return true;
}

// At this point all relevant mapping should be loaded in the virtual memory.
void SharedCache::ProcessEntryImages(const CacheEntry& entry)
{
	for (const auto& [imagePath, imageInfo] : entry.GetImages())
		ProcessEntryImage(imagePath, imageInfo);
}

// At this point all relevant mapping should be loaded in the virtual memory.
void SharedCache::ProcessEntryRegions(const CacheEntry& entry)
{
	auto entryHeader = entry.GetHeader();

	// Collect pool addresses as non image memory regions.
	for (size_t i = 0; i < entryHeader.branchPoolsCount; i++)
	{
		auto branchPoolAddr = entryHeader.branchPoolsOffset + (i * m_addressSize);
		auto header = SharedCacheMachOHeader::ParseHeaderForAddress(
			m_vm, branchPoolAddr, "dyld_shared_cache_branch_islands_" + std::to_string(i));
		// Stop processing branch pools if a header fails to parse.
		if (!header.has_value())
			break;

		// Gather all non image regions from the branch islands.
		for (const auto& segment : header->segments)
		{
			CacheRegion stubIslandRegion;
			stubIslandRegion.start = segment.vmaddr;
			stubIslandRegion.size = segment.filesize;
			char segName[17];
			memcpy(segName, segment.segname, 16);
			segName[16] = 0;
			std::string segNameStr = std::string(segName);
			stubIslandRegion.name = fmt::format("dyld_shared_cache_branch_islands_{}::{}", i, segNameStr);
			stubIslandRegion.flags = static_cast<BNSegmentFlag>(SegmentReadable | SegmentExecutable);
			stubIslandRegion.type = CacheRegionType::StubIsland;

			// Add the stub islands to the cache.
			AddRegion(std::move(stubIslandRegion));
		}
	}

	// Get the mapping.
	const auto& entryMappings = entry.GetMappings();

	// Add the mapping regions for the given entry type.
	// By default, we will just add all the mappings as read-write.
	switch (entry.GetType())
	{
	case CacheEntryType::DyldData:
	{
		size_t lastMappingIndex = 0;
		for (const auto& mapping : entryMappings)
		{
			CacheRegion mappingRegion;
			mappingRegion.start = mapping.address;
			mappingRegion.size = mapping.size;
			mappingRegion.name = fmt::format("{}::_data_{}", entry.GetFileName(), lastMappingIndex++);
			mappingRegion.flags = SegmentReadable;
			mappingRegion.type = CacheRegionType::DyldData;

			// Add the dyld data mapping as a region to the cache.
			AddRegion(std::move(mappingRegion));
		}
		break;
	}
	case CacheEntryType::Stub:
	{
		// Stub entry file, should only have a single mapping and no images.
		auto stubMapping = entryMappings[0];
		CacheRegion stubIslandRegion;
		stubIslandRegion.start = stubMapping.address;
		stubIslandRegion.size = stubMapping.size;
		stubIslandRegion.name = fmt::format("{}::_stubs", entry.GetFileName());
		stubIslandRegion.flags = static_cast<BNSegmentFlag>(SegmentReadable | SegmentExecutable);
		stubIslandRegion.type = CacheRegionType::StubIsland;

		// Add the stub island to the cache.
		AddRegion(std::move(stubIslandRegion));
	}
	default:
	{
		// Fill in all the gaps in the mapping with non image regions.
		size_t lastMappingIndex = 0;
		for (const auto& mapping : entryMappings)
		{
			// Add the remaining gap.
			CacheRegion nonImageRegion;
			nonImageRegion.start = mapping.address;
			nonImageRegion.size = mapping.size;
			nonImageRegion.name = fmt::format("{}::{}", entry.GetFileName(), lastMappingIndex++);
			nonImageRegion.flags = static_cast<BNSegmentFlag>(SegmentReadable | SegmentWritable);
			nonImageRegion.type = CacheRegionType::NonImage;
			AddRegion(std::move(nonImageRegion));
		}
		break;
	}
	}
}

void SharedCache::ProcessEntrySlideInfo(const CacheEntry& entry)
{
	auto slideInfoProcessor = SlideInfoProcessor(GetBaseAddress());
	slideInfoProcessor.ProcessEntry(*m_vm, entry);
}

void SharedCache::ProcessSymbols()
{
	// Populate the named symbols from the regular symbols map.
	m_namedSymbols.reserve(m_symbols.size());
	for (const auto& [address, symbol] : m_symbols)
		m_namedSymbols.emplace(symbol.name, address);
}

std::optional<CacheEntry> SharedCache::GetEntryContaining(const uint64_t address) const
{
	for (const auto& [_, entry] : m_entries)
	{
		for (const auto& mapping : entry.GetMappings())
		{
			if (address >= mapping.address && address < mapping.address + mapping.size)
				return entry;
		}
	}

	return std::nullopt;
}

std::optional<CacheEntry> SharedCache::GetEntryWithImage(const CacheImage& image) const
{
	for (const auto& [_, entry] : m_entries)
	{
		for (const auto& [_, currentImage] : entry.GetImages())
		{
			if (currentImage.address == image.headerAddress)
				return entry;
		}
	}

	return std::nullopt;
}

std::optional<CacheRegion> SharedCache::GetRegionAt(const uint64_t address) const
{
	const auto it = m_regions.find(address);
	if (it == m_regions.end())
		return std::nullopt;
	return it->second;
}

std::optional<CacheRegion> SharedCache::GetRegionContaining(const uint64_t address) const
{
	for (const auto& [range, region] : m_regions)
		if (address >= range.start && address < range.end)
			return region;
	return std::nullopt;
}

std::optional<CacheImage> SharedCache::GetImageAt(const uint64_t address) const
{
	const auto it = m_images.find(address);
	if (it == m_images.end())
		return std::nullopt;
	return it->second;
}

std::optional<CacheImage> SharedCache::GetImageContaining(const uint64_t address) const
{
	// TODO: What if we are using this on a shared region? Return a list of images?
	auto region = GetRegionContaining(address);
	if (region.has_value() && region->imageStart.has_value())
		return GetImageAt(*region->imageStart);
	return std::nullopt;
}

std::optional<CacheImage> SharedCache::GetImageWithName(const std::string& name) const
{
	for (const auto& [address, image] : m_images)
		if (image.path == name)
			return image;
	return std::nullopt;
}

std::optional<CacheSymbol> SharedCache::GetSymbolAt(uint64_t address) const
{
	const auto it = m_symbols.find(address);
	if (it == m_symbols.end())
		return std::nullopt;
	return it->second;
}

std::optional<CacheSymbol> SharedCache::GetSymbolWithName(const std::string& name) const
{
	const auto it = m_namedSymbols.find(name);
	if (it == m_namedSymbols.end())
		return std::nullopt;
	return GetSymbolAt(it->second);
}

CacheProcessor::CacheProcessor(Ref<BinaryView> view)
{
	m_view = std::move(view);
	m_logger = new Logger("SharedCache.Processor", m_view->GetFile()->GetSessionId());
}

bool CacheProcessor::ProcessCache(SharedCache& cache)
{
	// If we are in a project, use the project cache processor.
	if (m_view->GetFile()->GetProjectFile())
		return ProcessProjectCache(cache);
	return ProcessFileCache(cache);
}

bool CacheProcessor::ProcessFileCache(SharedCache& cache)
{
	// We assume that the binary view location has all the files we need.
	// If we ever want to allow users to override the shared cache file location
	// we should really make a cache processor constructor with entry file paths.
	std::string baseFilePath = m_view->GetFile()->GetOriginalFilename();
	std::string baseFileName = BaseFileName(baseFilePath);

	// Add this file to the entries
	try
	{
		auto baseEntry = CacheEntry::FromFile(baseFilePath, baseFileName, CacheEntryType::Primary);
		if (!baseEntry.has_value())
			return false;

		// Before we do anything else, add this to the cache so it's available to other entries.
		cache.AddEntry(std::move(*baseEntry));
	}
	catch (const std::exception& e)
	{
		// Just return false so the view init can continue.
		m_logger->LogErrorF("Failed to load base entry {}... {}", baseFileName, e.what());
		return false;
	}

	// Locate all possible related entry files and add them to the cache.
	std::filesystem::path basePath = std::filesystem::path(baseFilePath).parent_path();
	for (const auto& entry : std::filesystem::directory_iterator(basePath))
	{
		if (!entry.is_regular_file())
			continue;
		auto currentFilePath = entry.path().string();
		auto currentFileName = BaseFileName(currentFilePath);
		// Skip our base file, obviously.
		if (currentFilePath == baseFilePath)
			continue;
		// Filter files that don't contain the base file name i.e. "dyld_shared_cache_arm64e"
		if (currentFilePath.find(baseFileName) == std::string::npos)
			continue;
		// Skip map files, they contain some nice information... we don't use.
		if (entry.path().extension() == ".map")
			continue;
		// Skip bndb files!
		if (entry.path().extension() == ".bndb")
			continue;
		try
		{
			auto additionalEntry = CacheEntry::FromFile(currentFilePath, currentFileName, CacheEntryType::Secondary);
			if (!additionalEntry.has_value())
			{
				m_logger->LogErrorF("Failed to load entry {}...", currentFileName);
				continue;
			}

			// Add this file as an entry to the cache
			cache.AddEntry(std::move(*additionalEntry));
		}
		catch (const std::exception& e)
		{
			m_logger->LogErrorF("Failed to load entry {}... {}", currentFileName, e.what());
		}
	}

	return true;
}

bool CacheProcessor::ProcessProjectCache(SharedCache& cache)
{
	auto baseProjectFile = m_view->GetFile()->GetProjectFile();
	std::string baseFilePath = baseProjectFile->GetPathOnDisk();
	std::string baseFileName = baseProjectFile->GetName();

	// Remove the .bndb extension if present ("dyld_shared_cache_arm64e.bndb" => "dyld_shared_cache_arm64e)
	// TODO: This is a little annoying, we need to do this because the file accessor we have is seperate
	// TODO: from the view file accessor. If we either made it so that we can parse from the BNDB file accessor,
	// TODO: or... something better than this.
	if (baseFileName.find(".bndb") != std::string::npos)
	{
		baseFileName = baseFileName.substr(0, baseFileName.size() - 5);
		// Search for the backing file.
		for (const auto& projectFile : baseProjectFile->GetProject()->GetFiles())
		{
			auto projectFilePath = projectFile->GetPathOnDisk();
			auto projectFileName = projectFile->GetName();
			if (projectFileName == baseFileName)
			{
				// Use the real file instead.
				baseFilePath = projectFilePath;
				baseProjectFile = projectFile;
				break;
			}
		}
	}

	// Add this file to the entries
	auto baseEntry = CacheEntry::FromFile(baseFilePath, baseFileName, CacheEntryType::Primary);
	if (!baseEntry.has_value())
		return false;

	// Before we do anything else, add this to the cache so it's available to other entries.
	cache.AddEntry(std::move(*baseEntry));

	// Enumerate the project files folder to gather the necessary sub caches.
	const auto project = baseProjectFile->GetProject();
	const auto folder = baseProjectFile->GetFolder();
	for (const auto& projectFile : project->GetFiles())
	{
		auto projectFilePath = projectFile->GetPathOnDisk();
		auto projectFileName = projectFile->GetName();
		auto currentFolder = projectFile->GetFolder();
		// Skip our base project file, obviously.
		if (projectFile->GetId() == baseProjectFile->GetId())
			continue;
		// Filter files that don't contain the base file name i.e. "dyld_shared_cache_arm64e"
		if (projectFileName.find(baseFileName) == std::string::npos)
			continue;
		// Filter out .map files, they contain some nice info for rebasing... that we don't do.
		if (projectFileName.find(".map") != std::string::npos)
			continue;
		// Filter out .bndb files!
		if (projectFileName.find(".bndb") != std::string::npos)
			continue;
		// If both top level, or we are in the same folder as the base project file add it.
		if ((!folder && !currentFolder) || (folder && currentFolder))
		{
			try
			{
				auto additionalEntry = CacheEntry::FromFile(projectFilePath, projectFileName, CacheEntryType::Secondary);
				if (!additionalEntry.has_value())
				{
					m_logger->LogErrorF("Failed to load entry {}...", projectFileName);
					continue;
				}

				// Add this file as an entry to the cache
				cache.AddEntry(std::move(*additionalEntry));
			}
			catch (const std::exception& e)
			{}
		}
	}

	return true;
}
