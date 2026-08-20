//
// Created by kat on 5/21/23.
//

#include "kernelcacheapi.h"

using namespace BinaryNinja;
using namespace KernelCacheAPI;

BNKernelCacheImage ImageToApi(CacheImage image)
{
	BNKernelCacheImage apiImage {};
	apiImage.name = BNAllocString(image.name.c_str());
	apiImage.headerFileAddress = image.headerFileAddress;
	apiImage.headerVirtualAddress = image.headerVirtualAddress;
	return apiImage;
}

CacheImage ImageFromApi(BNKernelCacheImage image)
{
	CacheImage apiImage {};
	apiImage.name = image.name;
	apiImage.headerVirtualAddress = image.headerVirtualAddress;
	apiImage.headerFileAddress = image.headerFileAddress;
	return apiImage;
}

CacheSymbol SymbolFromApi(BNKernelCacheSymbol apiSymbol)
{
	CacheSymbol symbol;
	symbol.name = apiSymbol.name;
	symbol.address = apiSymbol.address;
	symbol.type = apiSymbol.symbolType;
	return symbol;
}

std::string KernelCacheAPI::GetSymbolTypeAsString(const BNSymbolType &type)
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

KernelCacheController::KernelCacheController(BNKernelCacheController *controller)
{
	m_object = controller;
}

KCRef<KernelCacheController> KernelCacheController::GetController(BinaryView &view)
{
	BNKernelCacheController *controller = BNGetKernelCacheController(view.GetObject());
	if (controller == nullptr)
		return nullptr;
	return new KernelCacheController(controller);
}

bool KernelCacheController::ApplyImage(BinaryView &view, const CacheImage &image)
{
	auto apiImage = ImageToApi(image);
	bool result = BNKernelCacheControllerApplyImage(m_object, view.GetObject(), &apiImage);
	BNKernelCacheFreeImage(apiImage);
	return result;
}

bool KernelCacheController::IsImageLoaded(const CacheImage &image) const
{
	auto apiImage = ImageToApi(image);
	bool result = BNKernelCacheControllerIsImageLoaded(m_object, &apiImage);
	BNKernelCacheFreeImage(apiImage);
	return result;
}

std::optional<CacheImage> KernelCacheController::GetImageAt(uint64_t address) const
{
	BNKernelCacheImage apiImage;
	if (!BNKernelCacheControllerGetImageAt(m_object, address, &apiImage))
		return std::nullopt;
	CacheImage image = ImageFromApi(apiImage);
	BNKernelCacheFreeImage(apiImage);
	return image;
}

std::optional<CacheImage> KernelCacheController::GetImageContaining(uint64_t address) const
{
	BNKernelCacheImage apiImage;
	if (!BNKernelCacheControllerGetImageContaining(m_object, address, &apiImage))
		return std::nullopt;
	CacheImage image = ImageFromApi(apiImage);
	BNKernelCacheFreeImage(apiImage);
	return image;
}

std::optional<CacheImage> KernelCacheController::GetImageWithName(const std::string &name) const
{
	BNKernelCacheImage apiImage;
	if (!BNKernelCacheControllerGetImageWithName(m_object, name.c_str(), &apiImage))
		return std::nullopt;
	CacheImage image = ImageFromApi(apiImage);
	BNKernelCacheFreeImage(apiImage);
	return image;
}

std::vector<std::string> KernelCacheController::GetImageDependencies(const CacheImage &image) const
{
	size_t count;
	BNKernelCacheImage apiImage = ImageToApi(image);
	char **dependencies = BNKernelCacheControllerGetImageDependencies(m_object, &apiImage, &count);
	BNKernelCacheFreeImage(apiImage);
	std::vector<std::string> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.emplace_back(dependencies[i]);
	BNFreeStringList(dependencies, count);
	return result;
}

std::optional<CacheSymbol> KernelCacheController::GetSymbolAt(uint64_t address) const
{
	BNKernelCacheSymbol apiSymbol;
	if (!BNKernelCacheControllerGetSymbolAt(m_object, address, &apiSymbol))
		return std::nullopt;
	CacheSymbol symbol = SymbolFromApi(apiSymbol);
	BNKernelCacheFreeSymbol(apiSymbol);
	return symbol;
}

std::optional<CacheSymbol> KernelCacheController::GetSymbolWithName(const std::string &name) const
{
	BNKernelCacheSymbol apiSymbol;
	if (!BNKernelCacheControllerGetSymbolWithName(m_object, name.c_str(), &apiSymbol))
		return std::nullopt;
	CacheSymbol symbol = SymbolFromApi(apiSymbol);
	BNKernelCacheFreeSymbol(apiSymbol);
	return symbol;
}

std::vector<CacheImage> KernelCacheController::GetImages() const
{
	size_t count;
	BNKernelCacheImage *images = BNKernelCacheControllerGetImages(m_object, &count);
	std::vector<CacheImage> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.emplace_back(ImageFromApi(images[i]));
	BNKernelCacheFreeImageList(images, count);
	return result;
}

std::vector<CacheImage> KernelCacheController::GetLoadedImages() const
{
	size_t count;
	BNKernelCacheImage *images = BNKernelCacheControllerGetLoadedImages(m_object, &count);
	std::vector<CacheImage> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.emplace_back(ImageFromApi(images[i]));
	BNKernelCacheFreeImageList(images, count);
	return result;
}

std::vector<CacheSymbol> KernelCacheController::GetSymbols() const
{
	size_t count;
	BNKernelCacheSymbol *symbols = BNKernelCacheControllerGetSymbols(m_object, &count);
	std::vector<CacheSymbol> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.emplace_back(SymbolFromApi(symbols[i]));
	BNKernelCacheFreeSymbolList(symbols, count);
	return result;
}
