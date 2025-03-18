//
// Created by kat on 5/21/23.
//

#include "sharedcacheapi.h"

namespace SharedCacheAPI {

	SharedCache::SharedCache(Ref<BinaryView> view) {
		m_object = BNGetSharedCache(view->GetObject());
	}

	BNDSCViewLoadProgress SharedCache::GetLoadProgress(Ref<BinaryView> view)
	{
		return BNDSCViewGetLoadProgress(view->GetFile()->GetSessionId());
	}

	uint64_t SharedCache::FastGetBackingCacheCount(Ref<BinaryView> view)
	{
		return BNDSCViewFastGetBackingCacheCount(view->GetObject());
	}

	bool SharedCache::LoadImageWithInstallName(std::string installName, bool skipObjC)
	{
		char* str = BNAllocString(installName.c_str());
		return BNDSCViewLoadImageWithInstallName(m_object, str, skipObjC);
	}

	bool SharedCache::LoadSectionAtAddress(uint64_t addr)
	{
		return BNDSCViewLoadSectionAtAddress(m_object, addr);
	}

	bool SharedCache::LoadImageContainingAddress(uint64_t addr, bool skipObjC)
	{
		return BNDSCViewLoadImageContainingAddress(m_object, addr, skipObjC);
	}

	std::vector<std::string> SharedCache::GetAvailableImages()
	{
		size_t count;
		char** value = BNDSCViewGetInstallNames(m_object, &count);
		if (value == nullptr)
		{
			return {};
		}

		std::vector<std::string> result;
		for (size_t i = 0; i < count; i++)
		{
			result.push_back(value[i]);
		}

		BNFreeStringList(value, count);
		return result;
	}

	void SharedCache::ProcessObjCSectionsForImageWithInstallName(std::string installName)
	{
		char* str = BNAllocString(installName.c_str());
		BNDSCViewProcessObjCSectionsForImageWithInstallName(m_object, str, true);
	}

	void SharedCache::ProcessAllObjCSections()
	{
		BNDSCViewProcessAllObjCSections(m_object);
	}

	std::vector<DSCMemoryRegion> SharedCache::GetLoadedMemoryRegions()
	{
		size_t count;
		BNDSCMappedMemoryRegion* value = BNDSCViewGetLoadedRegions(m_object, &count);
		if (value == nullptr)
		{
			return {};
		}

		std::vector<DSCMemoryRegion> result;
		for (size_t i = 0; i < count; i++)
		{
			DSCMemoryRegion region;
			region.vmAddress = value[i].vmAddress;
			region.size = value[i].size;
			region.prettyName = value[i].name;
			result.push_back(region);
		}

		BNDSCViewFreeLoadedRegions(value, count);
		return result;
	}
	std::vector<BackingCache> SharedCache::GetBackingCaches()
	{
		size_t count;
		BNDSCBackingCache* value = BNDSCViewGetBackingCaches(m_object, &count);
		if (value == nullptr)
		{
			return {};
		}

		std::vector<BackingCache> result;
		for (size_t i = 0; i < count; i++)
		{
			BackingCache cache;
			cache.path = value[i].path;
			cache.cacheType = value[i].cacheType;
			for (size_t j = 0; j < value[i].mappingCount; j++)
			{
				BackingCacheMapping mapping;
				mapping.vmAddress = value[i].mappings[j].vmAddress;
				mapping.size = value[i].mappings[j].size;
				mapping.fileOffset = value[i].mappings[j].fileOffset;
				cache.mappings.push_back(mapping);
			}
			result.push_back(cache);
		}

		BNDSCViewFreeBackingCaches(value, count);
		return result;
	}

	std::vector<DSCImage> SharedCache::GetImages()
	{
		size_t count;
		BNDSCImage* value = BNDSCViewGetAllImages(m_object, &count);
		if (value == nullptr)
		{
			return {};
		}

		std::vector<DSCImage> result;
		for (size_t i = 0; i < count; i++)
		{
			DSCImage img;
			img.name = value[i].name;
			img.headerAddress = value[i].headerAddress;
			for (size_t j = 0; j < value[i].mappingCount; j++)
			{
				DSCImageMemoryMapping mapping;
				mapping.filePath = value[i].mappings[j].filePath;
				mapping.name = value[i].mappings[j].name;
				mapping.vmAddress = value[i].mappings[j].vmAddress;
				mapping.rawViewOffset = value[i].mappings[j].rawViewOffset;
				mapping.size = value[i].mappings[j].size;
				mapping.loaded = value[i].mappings[j].loaded;
				img.mappings.push_back(mapping);
			}
			result.push_back(img);
		}

		BNDSCViewFreeAllImages(value, count);
		return result;
	}

	std::vector<DSCSymbol> SharedCache::LoadAllSymbolsAndWait()
	{
		size_t count;
		BNDSCSymbolRep* value = BNDSCViewLoadAllSymbolsAndWait(m_object, &count);
		if (value == nullptr)
		{
			return {};
		}

		std::vector<DSCSymbol> result;
		result.reserve(count);
		for (size_t i = 0; i < count; i++)
		{
			DSCSymbol sym;
			sym.address = value[i].address;
			sym.name = StringRef(BNDuplicateStringRef(value[i].name));
			sym.image = value[i].image;
			result.push_back(sym);
		}

		BNDSCViewFreeSymbols(value, count);
		return result;
	}

	std::string SharedCache::GetNameForAddress(uint64_t address)
	{
		char* name = BNDSCViewGetNameForAddress(m_object, address);
		if (name == nullptr)
			return {};
		std::string result = name;
		BNFreeString(name);
		return result;
	}

	std::string SharedCache::GetImageNameForAddress(uint64_t address)
	{
		char* name = BNDSCViewGetImageNameForAddress(m_object, address);
		if (name == nullptr)
			return {};
		std::string result = name;
		BNFreeString(name);
		return result;
	}

	std::optional<SharedCacheMachOHeader> SharedCache::GetMachOHeaderForImage(std::string name)
	{
		char* str = BNAllocString(name.c_str());
		char* outputStr = BNDSCViewGetImageHeaderForName(m_object, str);
		if (outputStr == nullptr)
			return {};
		std::string output = outputStr;
		BNFreeString(outputStr);
		if (output.empty())
			return {};

		return SharedCacheMachOHeader::LoadFromString(output);
	}

	std::optional<SharedCacheMachOHeader> SharedCache::GetMachOHeaderForAddress(uint64_t address)
	{
		char* outputStr = BNDSCViewGetImageHeaderForAddress(m_object, address);
		if (outputStr == nullptr)
			return {};
		std::string output = outputStr;
		BNFreeString(outputStr);
		if (output.empty())
			return {};
		return SharedCacheMachOHeader::LoadFromString(output);
	}

	BNDSCViewState SharedCache::GetState()
	{
		return BNDSCViewGetState(m_object);
	}

	void SharedCache::FindSymbolAtAddrAndApplyToAddr(uint64_t symbolLocation, uint64_t targetLocation, bool triggerReanalysis) const
	{
		BNDSCFindSymbolAtAddressAndApplyToAddress(m_object, symbolLocation, targetLocation, triggerReanalysis);
	}

}	// namespace SharedCacheAPI
