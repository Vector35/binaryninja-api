#include "SharedCacheController.h"
#include "../api/sharedcachecore.h"

using namespace BinaryNinja;
using namespace BinaryNinja::DSC;

BNSharedCacheImage ImageToApi(const CacheImage& image)
{
	BNSharedCacheImage apiImage;
	apiImage.name = BNAllocString(image.path.c_str());
	apiImage.headerAddress = image.headerAddress;
	apiImage.regionStartCount = image.regionStarts.size();
	uint64_t* regionStarts = new uint64_t[image.regionStarts.size()];
	for (size_t i = 0; i < image.regionStarts.size(); i++)
		regionStarts[i] = image.regionStarts[i];
	apiImage.regionStarts = regionStarts;
	return apiImage;
}

CacheImage ImageFromApi(const BNSharedCacheImage& image)
{
	CacheImage apiImage;
	apiImage.path = image.name;
	apiImage.headerAddress = image.headerAddress;
	apiImage.regionStarts.reserve(image.regionStartCount);
	for (size_t i = 0; i < image.regionStartCount; i++)
		apiImage.regionStarts.push_back(image.regionStarts[i]);
	apiImage.header = nullptr;
	return apiImage;
}

BNSharedCacheRegionType RegionTypeToApi(const CacheRegionType& regionType)
{
	switch (regionType)
	{
	case CacheRegionType::Image:
		return SharedCacheRegionTypeImage;
	case CacheRegionType::StubIsland:
		return SharedCacheRegionTypeStubIsland;
	case CacheRegionType::DyldData:
		return SharedCacheRegionTypeDyldData;
	default:
	case CacheRegionType::NonImage:
		return SharedCacheRegionTypeNonImage;
	}
}

CacheRegionType RegionTypeFromApi(const BNSharedCacheRegionType regionType)
{
	switch (regionType)
	{
	case SharedCacheRegionTypeImage:
		return CacheRegionType::Image;
	case SharedCacheRegionTypeStubIsland:
		return CacheRegionType::StubIsland;
	case SharedCacheRegionTypeDyldData:
		return CacheRegionType::DyldData;
	default:
	case SharedCacheRegionTypeNonImage:
		return CacheRegionType::NonImage;
	}
}

BNSharedCacheRegion RegionToApi(const CacheRegion& region)
{
	BNSharedCacheRegion apiRegion;
	apiRegion.vmAddress = region.start;
	apiRegion.name = BNAllocString(region.name.c_str());
	apiRegion.size = region.size;
	apiRegion.flags = region.flags;
	apiRegion.regionType = RegionTypeToApi(region.type);
	// If not associated with image this will be zeroed.
	apiRegion.imageStart = region.imageStart.value_or(0);
	return apiRegion;
}

CacheRegion RegionFromApi(const BNSharedCacheRegion& apiRegion)
{
	CacheRegion region;
	region.start = apiRegion.vmAddress;
	region.name = apiRegion.name;
	region.size = apiRegion.size;
	region.flags = apiRegion.flags;
	region.type = RegionTypeFromApi(apiRegion.regionType);
	return region;
}

BNSharedCacheSymbol SymbolToApi(const CacheSymbol& symbol)
{
	BNSharedCacheSymbol apiSymbol;
	apiSymbol.name = BNAllocString(symbol.name.c_str());
	apiSymbol.address = symbol.address;
	apiSymbol.symbolType = symbol.type;
	return apiSymbol;
}

CacheSymbol SymbolFromApi(const BNSharedCacheSymbol& apiSymbol)
{
	CacheSymbol symbol;
	symbol.name = apiSymbol.name;
	symbol.address = apiSymbol.address;
	symbol.type = apiSymbol.symbolType;
	return symbol;
}

BNSharedCacheEntryType EntryTypeToApi(const CacheEntryType& entryType)
{
	switch (entryType)
	{
	case CacheEntryType::Primary:
		return SharedCacheEntryTypePrimary;
	case CacheEntryType::Stub:
		return SharedCacheEntryTypeStub;
	case CacheEntryType::Symbols:
		return SharedCacheEntryTypeSymbols;
	case CacheEntryType::DyldData:
		return SharedCacheEntryTypeDyldData;
	default:
	case CacheEntryType::Secondary:
		return SharedCacheEntryTypeSecondary;
	}
}

BNSharedCacheMappingInfo MappingToApi(const dyld_cache_mapping_info& mapping)
{
	BNSharedCacheMappingInfo apiMapping;
	apiMapping.vmAddress = mapping.address;
	apiMapping.size = mapping.size;
	apiMapping.fileOffset = mapping.fileOffset;
	return apiMapping;
}

BNSharedCacheEntry EntryToApi(const CacheEntry& entry)
{
	BNSharedCacheEntry apiEntry;
	apiEntry.path = BNAllocString(entry.GetFilePath().c_str());
	apiEntry.entryType = EntryTypeToApi(entry.GetType());
	const auto& mappings = entry.GetMappings();
	apiEntry.mappingCount = mappings.size();
	apiEntry.mappings = new BNSharedCacheMappingInfo[mappings.size()];
	for (size_t i = 0; i < mappings.size(); i++)
		apiEntry.mappings[i] = MappingToApi(mappings[i]);
	return apiEntry;
}

extern "C"
{
	BNSharedCacheController* BNGetSharedCacheController(BNBinaryView* data)
	{
		Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
		auto controller = SharedCacheController::FromView(*view);
		if (!controller)
			return nullptr;
		return DSC_API_OBJECT_REF(controller);
	}

	BNSharedCacheController* BNNewSharedCacheControllerReference(BNSharedCacheController* controller)
	{
		return DSC_API_OBJECT_NEW_REF(controller);
	}

	void BNFreeSharedCacheControllerReference(BNSharedCacheController* controller)
	{
		DSC_API_OBJECT_FREE(controller);
	}

	bool BNSharedCacheControllerApplyImage(
		BNSharedCacheController* controller, BNBinaryView* data, BNSharedCacheImage* image)
	{
		Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
		// LoadImage will use the header, lets do everyone a favor and use the existing image!
		if (const auto realImage = controller->object->GetCache().GetImageAt(image->headerAddress))
			return controller->object->ApplyImage(*view, *realImage);
		// They gave us an unknown image, we will not have header information.
		return controller->object->ApplyImage(*view, ImageFromApi(*image));
	}

	bool BNSharedCacheControllerApplyRegion(
		BNSharedCacheController* controller, BNBinaryView* data, BNSharedCacheRegion* region)
	{
		Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
		return controller->object->ApplyRegion(*view, RegionFromApi(*region));
	}

	bool BNSharedCacheControllerIsRegionLoaded(BNSharedCacheController* controller, BNSharedCacheRegion* region)
	{
		return controller->object->IsRegionLoaded(RegionFromApi(*region));
	}

	bool BNSharedCacheControllerIsImageLoaded(BNSharedCacheController* controller, BNSharedCacheImage* image)
	{
		return controller->object->IsImageLoaded(ImageFromApi(*image));
	}

	bool BNSharedCacheControllerGetRegionAt(
		BNSharedCacheController* controller, uint64_t address, BNSharedCacheRegion* outRegion)
	{
		const auto region = controller->object->GetCache().GetRegionAt(address);
		if (!region)
			return false;
		*outRegion = RegionToApi(*region);
		return true;
	}

	bool BNSharedCacheControllerGetRegionContaining(
		BNSharedCacheController* controller, uint64_t address, BNSharedCacheRegion* outRegion)
	{
		const auto region = controller->object->GetCache().GetRegionContaining(address);
		if (!region)
			return false;
		*outRegion = RegionToApi(*region);
		return true;
	}

	BNSharedCacheRegion* BNSharedCacheControllerGetRegions(BNSharedCacheController* controller, size_t* count)
	{
		const auto& regions = controller->object->GetCache().GetRegions();
		*count = regions.size();
		BNSharedCacheRegion* apiRegions = new BNSharedCacheRegion[*count];
		int idx = 0;
		for (const auto& [_, region] : regions)
			apiRegions[idx++] = RegionToApi(region);
		return apiRegions;
	}

	BNSharedCacheRegion* BNSharedCacheControllerGetLoadedRegions(BNSharedCacheController* controller, size_t* count)
	{
		const auto& loadedRegionStarts = controller->object->GetLoadedRegions();

		// TODO: This translation should likely exist in the core cache controller class?
		std::vector<CacheRegion> loadedRegions;
		for (auto start : loadedRegionStarts)
		{
			auto region = controller->object->GetCache().GetRegionAt(start);
			if (region)
				loadedRegions.push_back(*region);
		}

		*count = loadedRegions.size();
		BNSharedCacheRegion* apiRegions = new BNSharedCacheRegion[*count];
		// I am too lazy to add a real conversion here.
		int idx = 0;
		for (const auto& region : loadedRegions)
		{
			apiRegions[idx] = RegionToApi(region);
			idx++;
		}
		return apiRegions;
	}

	uint64_t* BNSharedCacheAllocRegionList(uint64_t* list, size_t count)
	{
		uint64_t* newList = new uint64_t[count];
		for (size_t i = 0; i < count; i++)
			newList[i] = list[i];
		return newList;
	}

	void BNSharedCacheFreeRegion(BNSharedCacheRegion region)
	{
		BNFreeString(region.name);
	}

	void BNSharedCacheFreeRegionList(BNSharedCacheRegion* regions, size_t count)
	{
		for (size_t i = 0; i < count; i++)
			BNSharedCacheFreeRegion(regions[i]);
		delete[] regions;
	}

	bool BNSharedCacheControllerGetImageAt(
		BNSharedCacheController* controller, uint64_t address, BNSharedCacheImage* outImage)
	{
		const auto image = controller->object->GetCache().GetImageAt(address);
		if (!image)
			return false;
		*outImage = ImageToApi(*image);
		return true;
	}

	bool BNSharedCacheControllerGetImageContaining(
		BNSharedCacheController* controller, uint64_t address, BNSharedCacheImage* outImage)
	{
		const auto image = controller->object->GetCache().GetImageContaining(address);
		if (!image)
			return false;
		*outImage = ImageToApi(*image);
		return true;
	}

	bool BNSharedCacheControllerGetImageWithName(
		BNSharedCacheController* controller, const char* name, BNSharedCacheImage* outImage)
	{
		const auto image = controller->object->GetCache().GetImageWithName(name);
		if (!image)
			return false;
		*outImage = ImageToApi(*image);
		return true;
	}

	char** BNSharedCacheControllerGetImageDependencies(
		BNSharedCacheController* controller, BNSharedCacheImage* image, size_t* count)
	{
		// GetDependencies will use the header, lets do everyone a favor and use the existing image!
		const auto realImage = controller->object->GetCache().GetImageAt(image->headerAddress);
		if (!realImage.has_value())
			return nullptr;
		const auto dependencies = realImage->GetDependencies();

		std::vector<const char*> dependencyPtrs;
		dependencyPtrs.reserve(dependencies.size());
		for (const auto& dependency : dependencies)
			dependencyPtrs.push_back(dependency.c_str());
		*count = dependencyPtrs.size();
		return BNAllocStringList(dependencyPtrs.data(), dependencyPtrs.size());
	}

	BNSharedCacheImage* BNSharedCacheControllerGetImages(BNSharedCacheController* controller, size_t* count)
	{
		const auto& images = controller->object->GetCache().GetImages();
		*count = images.size();
		BNSharedCacheImage* apiImages = new BNSharedCacheImage[*count];
		size_t idx = 0;
		for (const auto& [_, image] : images)
			apiImages[idx++] = ImageToApi(image);
		return apiImages;
	}

	BNSharedCacheImage* BNSharedCacheControllerGetLoadedImages(BNSharedCacheController* controller, size_t* count)
	{
		const auto& loadedImageStarts = controller->object->GetLoadedImages();

		// TODO: This translation should likely exist in the core cache controller class?
		std::vector<CacheImage> loadedImages;
		for (auto start : loadedImageStarts)
		{
			auto image = controller->object->GetCache().GetImageAt(start);
			if (image)
				loadedImages.push_back(*image);
		}

		*count = loadedImages.size();
		BNSharedCacheImage* apiImages = new BNSharedCacheImage[*count];
		for (size_t i = 0; i < *count; i++)
			apiImages[i] = ImageToApi(loadedImages[i]);
		return apiImages;
	}

	void BNSharedCacheFreeImage(BNSharedCacheImage image)
	{
		BNFreeString(image.name);
		delete[] image.regionStarts;
	}

	void BNSharedCacheFreeImageList(BNSharedCacheImage* images, size_t count)
	{
		for (size_t i = 0; i < count; i++)
			BNSharedCacheFreeImage(images[i]);
		delete[] images;
	}

	bool BNSharedCacheControllerGetSymbolAt(
		BNSharedCacheController* controller, uint64_t address, BNSharedCacheSymbol* outSymbol)
	{
		const auto symbol = controller->object->GetCache().GetSymbolAt(address);
		if (!symbol)
			return false;
		*outSymbol = SymbolToApi(*symbol);
		return true;
	}

	bool BNSharedCacheControllerGetSymbolWithName(
		BNSharedCacheController* controller, const char* name, BNSharedCacheSymbol* outSymbol)
	{
		const auto symbol = controller->object->GetCache().GetSymbolWithName(name);
		if (!symbol)
			return false;
		*outSymbol = SymbolToApi(*symbol);
		return true;
	}

	BNSharedCacheSymbol* BNSharedCacheControllerGetSymbols(BNSharedCacheController* controller, size_t* count)
	{
		const auto& symbols = controller->object->GetCache().GetSymbols();
		*count = symbols.size();
		BNSharedCacheSymbol* apiSymbols = new BNSharedCacheSymbol[*count];
		size_t idx = 0;
		for (const auto& [_, symbol] : symbols)
			apiSymbols[idx++] = SymbolToApi(symbol);
		return apiSymbols;
	}


	void BNSharedCacheFreeSymbol(BNSharedCacheSymbol symbol)
	{
		BNFreeString(symbol.name);
	}

	void BNSharedCacheFreeSymbolList(BNSharedCacheSymbol* symbols, size_t count)
	{
		for (size_t i = 0; i < count; i++)
			BNSharedCacheFreeSymbol(symbols[i]);
		delete[] symbols;
	}

	BNSharedCacheEntry* BNSharedCacheControllerGetEntries(BNSharedCacheController* controller, size_t* count)
	{
		const auto& entries = controller->object->GetCache().GetEntries();
		*count = entries.size();
		BNSharedCacheEntry* apiEntries = new BNSharedCacheEntry[*count];
		size_t idx = 0;
		for (const auto& [_, entry] : entries)
			apiEntries[idx++] = EntryToApi(entry);
		return apiEntries;
	}

	void BNSharedCacheFreeEntry(BNSharedCacheEntry entry)
	{
		BNFreeString(entry.path);
		delete[] entry.mappings;
	}

	void BNSharedCacheFreeEntryList(BNSharedCacheEntry* entries, size_t count)
	{
		for (size_t i = 0; i < count; i++)
			BNSharedCacheFreeEntry(entries[i]);
		delete[] entries;
	}
};
