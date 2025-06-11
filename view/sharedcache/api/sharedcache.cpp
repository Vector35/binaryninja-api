//
// Created by kat on 5/21/23.
//

#include "sharedcacheapi.h"

using namespace BinaryNinja;
using namespace SharedCacheAPI;

BNSharedCacheImage ImageToApi(CacheImage image)
{
	BNSharedCacheImage apiImage {};
	apiImage.name = BNAllocString(image.name.c_str());
	apiImage.headerAddress = image.headerAddress;
	apiImage.regionStartCount = image.regionStarts.size();
	uint64_t *regionStarts = new uint64_t[image.regionStarts.size()];
	for (size_t i = 0; i < image.regionStarts.size(); i++)
		regionStarts[i] = image.regionStarts[i];
	apiImage.regionStarts = BNSharedCacheAllocRegionList(regionStarts, image.regionStarts.size());
	delete[] regionStarts;
	return apiImage;
}

CacheImage ImageFromApi(BNSharedCacheImage image)
{
	CacheImage apiImage {};
	apiImage.name = image.name;
	apiImage.headerAddress = image.headerAddress;
	apiImage.regionStarts.reserve(image.regionStartCount);
	for (size_t i = 0; i < image.regionStartCount; i++)
		apiImage.regionStarts.push_back(image.regionStarts[i]);
	return apiImage;
}

BNSharedCacheRegion RegionToApi(const CacheRegion &region)
{
	BNSharedCacheRegion apiRegion {};
	apiRegion.vmAddress = region.start;
	apiRegion.name = BNAllocString(region.name.c_str());
	apiRegion.size = region.size;
	apiRegion.flags = region.flags;
	apiRegion.regionType = region.type;
	// If not associated with image this will be zeroed.
	apiRegion.imageStart = region.imageStart.value_or(0);
	return apiRegion;
}

CacheRegion RegionFromApi(BNSharedCacheRegion apiRegion)
{
	CacheRegion region {};
	region.start = apiRegion.vmAddress;
	region.name = apiRegion.name;
	region.size = apiRegion.size;
	region.flags = apiRegion.flags;
	region.type = apiRegion.regionType;
	return region;
}

BNSharedCacheMappingInfo MappingToApi(const CacheMappingInfo &mapping)
{
	BNSharedCacheMappingInfo apiMapping {};
	apiMapping.vmAddress = mapping.vmAddress;
	apiMapping.size = mapping.size;
	apiMapping.fileOffset = mapping.fileOffset;
	return apiMapping;
}

CacheMappingInfo MappingFromApi(BNSharedCacheMappingInfo apiMapping)
{
	CacheMappingInfo mapping {};
	mapping.vmAddress = apiMapping.vmAddress;
	mapping.size = apiMapping.size;
	mapping.fileOffset = apiMapping.fileOffset;
	return mapping;
}

BNSharedCacheEntry EntryToApi(const CacheEntry &entry)
{
	BNSharedCacheEntry apiEntry {};
	apiEntry.path = BNAllocString(entry.path.c_str());
	apiEntry.name = BNAllocString(entry.name.c_str());
	apiEntry.entryType = entry.entryType;
	const auto &mappings = entry.mappings;
	apiEntry.mappingCount = mappings.size();
	// TODO: If we alloc then the core cannot delete.
	apiEntry.mappings = new BNSharedCacheMappingInfo[mappings.size()];
	for (size_t i = 0; i < mappings.size(); i++)
		apiEntry.mappings[i] = MappingToApi(mappings[i]);
	return apiEntry;
}

CacheEntry EntryFromApi(BNSharedCacheEntry apiEntry)
{
	CacheEntry entry {};
	entry.path = apiEntry.path;
	entry.name = apiEntry.name;
	entry.entryType = apiEntry.entryType;
	entry.mappings.reserve(apiEntry.mappingCount);
	for (size_t i = 0; i < apiEntry.mappingCount; i++)
		entry.mappings.push_back(MappingFromApi(apiEntry.mappings[i]));
	return entry;
}

CacheSymbol SymbolFromApi(BNSharedCacheSymbol apiSymbol)
{
	CacheSymbol symbol;
	symbol.name = apiSymbol.name;
	symbol.address = apiSymbol.address;
	symbol.type = apiSymbol.symbolType;
	return symbol;
}

std::string SharedCacheAPI::GetRegionTypeAsString(const BNSharedCacheRegionType &type)
{
	switch (type)
	{
	case SharedCacheRegionTypeImage:
		return "Image";
	case SharedCacheRegionTypeStubIsland:
		return "StubIsland";
	case SharedCacheRegionTypeDyldData:
		return "DyldData";
	case SharedCacheRegionTypeNonImage:
		return "NonImage";
	default:
		return "Unknown";
	}
}

std::pair<std::string, Ref<Type>> CacheSymbol::DemangledName(BinaryView &view) const
{
	QualifiedName qname;
	Ref<Type> outType = nullptr;
	std::string shortName = name;
	if (DemangleGeneric(view.GetDefaultArchitecture(), name, outType, qname, &view, true))
		shortName = qname.GetString();
	return {shortName, outType};
}

Ref<Symbol> CacheSymbol::GetBNSymbol(BinaryView &view) const
{
	auto [shortName, _] = DemangledName(view);
	return new Symbol(type, shortName, shortName, name, address, nullptr);
}

std::string SharedCacheAPI::GetSymbolTypeAsString(const BNSymbolType &type)
{
	// NOTE: We currently only use the function and data symbol for cache symbols.
	// update this if that changes.
	switch (type)
	{
	case FunctionSymbol:
		return "Function";
	case DataSymbol:
		return "Data";
	default:
		return "Unknown";
	}
}

SharedCacheController::SharedCacheController(BNSharedCacheController *controller)
{
	m_object = controller;
}

DSCRef<SharedCacheController> SharedCacheController::GetController(BinaryView &view)
{
	BNSharedCacheController *controller = BNGetSharedCacheController(view.GetObject());
	if (controller == nullptr)
		return nullptr;
	return new SharedCacheController(controller);
}

bool SharedCacheController::ApplyRegion(BinaryView &view, const CacheRegion &region)
{
	auto apiRegion = RegionToApi(region);
	bool result = BNSharedCacheControllerApplyRegion(m_object, view.GetObject(), &apiRegion);
	BNSharedCacheFreeRegion(apiRegion);
	return result;
}

bool SharedCacheController::ApplyImage(BinaryView &view, const CacheImage &image)
{
	auto apiImage = ImageToApi(image);
	bool result = BNSharedCacheControllerApplyImage(m_object, view.GetObject(), &apiImage);
	BNSharedCacheFreeImage(apiImage);
	return result;
}

bool SharedCacheController::IsRegionLoaded(const CacheRegion &region) const
{
	auto apiRegion = RegionToApi(region);
	bool result = BNSharedCacheControllerIsRegionLoaded(m_object, &apiRegion);
	BNSharedCacheFreeRegion(apiRegion);
	return result;
}

bool SharedCacheController::IsImageLoaded(const CacheImage &image) const
{
	auto apiImage = ImageToApi(image);
	bool result = BNSharedCacheControllerIsImageLoaded(m_object, &apiImage);
	BNSharedCacheFreeImage(apiImage);
	return result;
}

std::optional<CacheRegion> SharedCacheController::GetRegionAt(uint64_t address) const
{
	BNSharedCacheRegion apiRegion;
	if (!BNSharedCacheControllerGetRegionAt(m_object, address, &apiRegion))
		return std::nullopt;
	CacheRegion region = RegionFromApi(apiRegion);
	BNSharedCacheFreeRegion(apiRegion);
	return region;
}

std::optional<CacheRegion> SharedCacheController::GetRegionContaining(uint64_t address) const
{
	BNSharedCacheRegion apiRegion;
	if (!BNSharedCacheControllerGetRegionContaining(m_object, address, &apiRegion))
		return std::nullopt;
	CacheRegion region = RegionFromApi(apiRegion);
	BNSharedCacheFreeRegion(apiRegion);
	return region;
}

std::optional<CacheImage> SharedCacheController::GetImageAt(uint64_t address) const
{
	BNSharedCacheImage apiImage;
	if (!BNSharedCacheControllerGetImageAt(m_object, address, &apiImage))
		return std::nullopt;
	CacheImage image = ImageFromApi(apiImage);
	BNSharedCacheFreeImage(apiImage);
	return image;
}

std::optional<CacheImage> SharedCacheController::GetImageContaining(uint64_t address) const
{
	BNSharedCacheImage apiImage;
	if (!BNSharedCacheControllerGetImageContaining(m_object, address, &apiImage))
		return std::nullopt;
	CacheImage image = ImageFromApi(apiImage);
	BNSharedCacheFreeImage(apiImage);
	return image;
}

std::optional<CacheImage> SharedCacheController::GetImageWithName(const std::string &name) const
{
	BNSharedCacheImage apiImage;
	if (!BNSharedCacheControllerGetImageWithName(m_object, name.c_str(), &apiImage))
		return std::nullopt;
	CacheImage image = ImageFromApi(apiImage);
	BNSharedCacheFreeImage(apiImage);
	return image;
}

std::vector<std::string> SharedCacheController::GetImageDependencies(const CacheImage &image) const
{
	size_t count;
	BNSharedCacheImage apiImage = ImageToApi(image);
	char **dependencies = BNSharedCacheControllerGetImageDependencies(m_object, &apiImage, &count);
	BNSharedCacheFreeImage(apiImage);
	std::vector<std::string> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.emplace_back(dependencies[i]);
	BNFreeStringList(dependencies, count);
	return result;
}

std::optional<CacheSymbol> SharedCacheController::GetSymbolAt(uint64_t address) const
{
	BNSharedCacheSymbol apiSymbol;
	if (!BNSharedCacheControllerGetSymbolAt(m_object, address, &apiSymbol))
		return std::nullopt;
	CacheSymbol symbol = SymbolFromApi(apiSymbol);
	BNSharedCacheFreeSymbol(apiSymbol);
	return symbol;
}

std::optional<CacheSymbol> SharedCacheController::GetSymbolWithName(const std::string &name) const
{
	BNSharedCacheSymbol apiSymbol;
	if (!BNSharedCacheControllerGetSymbolWithName(m_object, name.c_str(), &apiSymbol))
		return std::nullopt;
	CacheSymbol symbol = SymbolFromApi(apiSymbol);
	BNSharedCacheFreeSymbol(apiSymbol);
	return symbol;
}

std::vector<CacheEntry> SharedCacheController::GetEntries() const
{
	size_t count;
	BNSharedCacheEntry *entries = BNSharedCacheControllerGetEntries(m_object, &count);
	std::vector<CacheEntry> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.emplace_back(EntryFromApi(entries[i]));
	BNSharedCacheFreeEntryList(entries, count);
	return result;
}

std::vector<CacheRegion> SharedCacheController::GetLoadedRegions() const
{
	size_t count;
	BNSharedCacheRegion *regions = BNSharedCacheControllerGetLoadedRegions(m_object, &count);
	std::vector<CacheRegion> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.emplace_back(RegionFromApi(regions[i]));
	BNSharedCacheFreeRegionList(regions, count);
	return result;
}

std::vector<CacheRegion> SharedCacheController::GetRegions() const
{
	size_t count;
	BNSharedCacheRegion *regions = BNSharedCacheControllerGetRegions(m_object, &count);
	std::vector<CacheRegion> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.emplace_back(RegionFromApi(regions[i]));
	BNSharedCacheFreeRegionList(regions, count);
	return result;
}

std::vector<CacheImage> SharedCacheController::GetImages() const
{
	size_t count;
	BNSharedCacheImage *images = BNSharedCacheControllerGetImages(m_object, &count);
	std::vector<CacheImage> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.emplace_back(ImageFromApi(images[i]));
	BNSharedCacheFreeImageList(images, count);
	return result;
}

std::vector<CacheImage> SharedCacheController::GetLoadedImages() const
{
	size_t count;
	BNSharedCacheImage *images = BNSharedCacheControllerGetLoadedImages(m_object, &count);
	std::vector<CacheImage> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.emplace_back(ImageFromApi(images[i]));
	BNSharedCacheFreeImageList(images, count);
	return result;
}

std::vector<CacheSymbol> SharedCacheController::GetSymbols() const
{
	size_t count;
	BNSharedCacheSymbol *symbols = BNSharedCacheControllerGetSymbols(m_object, &count);
	std::vector<CacheSymbol> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.emplace_back(SymbolFromApi(symbols[i]));
	BNSharedCacheFreeSymbolList(symbols, count);
	return result;
}
