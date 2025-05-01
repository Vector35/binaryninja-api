//
// Created by kat on 5/21/23.
//

#include "kernelcacheapi.h"

namespace KernelCacheAPI {

	KernelCache::KernelCache(Ref<BinaryView> view) {
		m_object = BNGetKernelCache(view->GetObject());
	}

	BNKCViewLoadProgress KernelCache::GetLoadProgress(Ref<BinaryView> view)
	{
		return BNKCViewGetLoadProgress(view->GetFile()->GetSessionId());
	}

	uint64_t KernelCache::FastGetImageCount(Ref<BinaryView> view)
	{
		return BNKCViewFastGetImageCount(view->GetObject());
	}

	bool KernelCache::LoadImageWithInstallName(std::string installName)
	{
		char* str = BNAllocString(installName.c_str());
		return BNKCViewLoadImageWithInstallName(m_object, str);
	}

	bool KernelCache::LoadImageContainingAddress(uint64_t addr)
	{
		return BNKCViewLoadImageContainingAddress(m_object, addr);
	}

	std::vector<std::string> KernelCache::GetAvailableImages()
	{
		size_t count;
		char** value = BNKCViewGetInstallNames(m_object, &count);
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

	bool KernelCache::IsImageLoaded(const uint64_t address) const
	{
	    return BNKCViewIsImageLoaded(m_object, address);
	}

	std::vector<KCImage> KernelCache::GetImages()
	{
		size_t count;
		BNKCImage* value = BNKCViewGetAllImages(m_object, &count);
		if (value == nullptr)
		{
			return {};
		}

		std::vector<KCImage> result;
		for (size_t i = 0; i < count; i++)
		{
			KCImage img;
			img.name = value[i].name;
			img.headerFileAddress = value[i].headerFileAddress;
			for (size_t j = 0; j < value[i].mappingCount; j++)
			{
				KCImageMemoryMapping mapping;
				mapping.name = value[i].mappings[j].name;
				mapping.vmAddress = value[i].mappings[j].vmAddress;
				mapping.rawViewOffset = value[i].mappings[j].rawViewOffset;
				mapping.size = value[i].mappings[j].size;
				mapping.loaded = value[i].mappings[j].loaded;
				img.mappings.push_back(mapping);
			}
			result.push_back(img);
		}

		BNKCViewFreeAllImages(value, count);
		return result;
	}

	std::vector<KCImage> KernelCache::GetLoadedImages()
	{
		size_t count;
		auto images = BNKCViewGetLoadedImages(m_object, &count);
		if (images == nullptr)
		{
			return {};
		}
		std::vector<KCImage> result;
		for (size_t i = 0; i < count; i++)
		{
			KCImage img;
			img.name = images[i].name;
			img.headerFileAddress = images[i].headerFileAddress;
			for (size_t j = 0; j < images[i].mappingCount; j++)
			{
				KCImageMemoryMapping mapping;
				mapping.name = images[i].mappings[j].name;
				mapping.vmAddress = images[i].mappings[j].vmAddress;
				mapping.rawViewOffset = images[i].mappings[j].rawViewOffset;
				mapping.size = images[i].mappings[j].size;
				mapping.loaded = images[i].mappings[j].loaded;
				img.mappings.push_back(mapping);
			}
			result.push_back(img);
		}
		BNKCViewFreeAllImages(images, count);

		return result;
	}

	std::vector<KCSymbol> KernelCache::LoadAllSymbolsAndWait()
	{
		size_t count;
		BNKCSymbolRep* value = BNKCViewLoadAllSymbolsAndWait(m_object, &count);
		if (value == nullptr)
		{
			return {};
		}

		std::vector<KCSymbol> result;
		for (size_t i = 0; i < count; i++)
		{
			KCSymbol sym;
			sym.address = value[i].address;
			sym.name = value[i].name;
			sym.image = value[i].image;
			result.push_back(sym);
		}

		BNKCViewFreeSymbols(value, count);
		return result;
	}

	std::string KernelCache::GetNameForAddress(uint64_t address)
	{
		char* name = BNKCViewGetNameForAddress(m_object, address);
		if (name == nullptr)
			return {};
		std::string result = name;
		BNFreeString(name);
		return result;
	}

	std::string KernelCache::GetImageNameForAddress(uint64_t address)
	{
		char* name = BNKCViewGetImageNameForAddress(m_object, address);
		if (name == nullptr)
			return {};
		std::string result = name;
		BNFreeString(name);
		return result;
	}

	std::optional<KernelCacheMachOHeader> KernelCache::GetMachOHeaderForImage(std::string name)
	{
		char* str = BNAllocString(name.c_str());
		char* outputStr = BNKCViewGetImageHeaderForName(m_object, str);
		if (outputStr == nullptr)
			return {};
		std::string output = outputStr;
		BNFreeString(outputStr);
		if (output.empty())
			return {};
		KernelCacheMachOHeader header = KernelCacheMachOHeader::LoadFromString(output);
		return header;
	}

	std::optional<KernelCacheMachOHeader> KernelCache::GetMachOHeaderForAddress(uint64_t address)
	{
		char* outputStr = BNKCViewGetImageHeaderForAddress(m_object, address);
		if (outputStr == nullptr)
			return {};
		std::string output = outputStr;
		BNFreeString(outputStr);
		if (output.empty())
			return {};
		KernelCacheMachOHeader header = KernelCacheMachOHeader::LoadFromString(output);
		return header;
	}

	BNKCViewState KernelCache::GetState()
	{
		return BNKCViewGetState(m_object);
	}

}	// namespace KernelCacheAPI
