#include "KernelCacheController.h"
#include "../api/kernelcachecore.h"

using namespace BinaryNinja;
using namespace BinaryNinja::KC;

BNKernelCacheImage ImageToApi(const CacheImage& image)
{
	BNKernelCacheImage apiImage;
	apiImage.name = BNAllocString(image.path.c_str());
	apiImage.headerVirtualAddress = image.headerVirtualAddress;
	apiImage.headerFileAddress = image.headerFileAddress;
	return apiImage;
}

CacheImage ImageFromApi(const BNKernelCacheImage& image)
{
	CacheImage apiImage;
	apiImage.path = image.name;
	apiImage.headerVirtualAddress = image.headerVirtualAddress;
	apiImage.headerFileAddress = image.headerFileAddress;
	apiImage.header = nullptr;
	return apiImage;
}

BNKernelCacheSymbol SymbolToApi(const CacheSymbol& symbol)
{
	BNKernelCacheSymbol apiSymbol;
	apiSymbol.name = BNAllocString(symbol.name.c_str());
	apiSymbol.address = symbol.address;
	apiSymbol.symbolType = symbol.type;
	return apiSymbol;
}

CacheSymbol SymbolFromApi(const BNKernelCacheSymbol& apiSymbol)
{
	CacheSymbol symbol;
	symbol.name = apiSymbol.name;
	symbol.address = apiSymbol.address;
	symbol.type = apiSymbol.symbolType;
	return symbol;
}

extern "C"
{
	BNKernelCacheController* BNGetKernelCacheController(BNBinaryView* data)
	{
		Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
		auto controller = KernelCacheController::FromView(*view);
		if (!controller)
			return nullptr;
		return KC_API_OBJECT_REF(controller);
	}

	BNKernelCacheController* BNNewKernelCacheControllerReference(BNKernelCacheController* controller)
	{
		return KC_API_OBJECT_NEW_REF(controller);
	}

	void BNFreeKernelCacheControllerReference(BNKernelCacheController* controller)
	{
		KC_API_OBJECT_FREE(controller);
	}

	bool BNKernelCacheControllerApplyImage(
		BNKernelCacheController* controller, BNBinaryView* data, BNKernelCacheImage* image)
	{
		Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
		// LoadImage will use the header, lets do everyone a favor and use the existing image!
		if (const auto realImage = controller->object->GetCache().GetImageAt(image->headerVirtualAddress))
			return controller->object->ApplyImage(*view, *realImage);
		// They gave us an unknown image, we will not have header information.
		return controller->object->ApplyImage(*view, ImageFromApi(*image));
	}
	bool BNKernelCacheControllerIsImageLoaded(BNKernelCacheController* controller, BNKernelCacheImage* image)
	{
		return controller->object->IsImageLoaded(ImageFromApi(*image));
	}

	bool BNKernelCacheControllerGetImageAt(
		BNKernelCacheController* controller, uint64_t address, BNKernelCacheImage* outImage)
	{
		const auto image = controller->object->GetCache().GetImageAt(address);
		if (!image)
			return false;
		*outImage = ImageToApi(*image);
		return true;
	}

	bool BNKernelCacheControllerGetImageContaining(
		BNKernelCacheController* controller, uint64_t address, BNKernelCacheImage* outImage)
	{
		const auto image = controller->object->GetCache().GetImageContaining(address);
		if (!image)
			return false;
		*outImage = ImageToApi(*image);
		return true;
	}

	bool BNKernelCacheControllerGetImageWithName(
		BNKernelCacheController* controller, const char* name, BNKernelCacheImage* outImage)
	{
		const auto image = controller->object->GetCache().GetImageWithName(name);
		if (!image)
			return false;
		*outImage = ImageToApi(*image);
		return true;
	}

	char** BNKernelCacheControllerGetImageDependencies(
		BNKernelCacheController* controller, BNKernelCacheImage* image, size_t* count)
	{
		// GetDependencies will use the header, lets do everyone a favor and use the existing image!
		const auto realImage = controller->object->GetCache().GetImageAt(image->headerFileAddress);
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

	BNKernelCacheImage* BNKernelCacheControllerGetImages(BNKernelCacheController* controller, size_t* count)
	{
		const auto& images = controller->object->GetCache().GetImages();
		*count = images.size();
		BNKernelCacheImage* apiImages = new BNKernelCacheImage[*count];
		size_t idx = 0;
		for (const auto& [_, image] : images)
			apiImages[idx++] = ImageToApi(image);
		return apiImages;
	}

	BNKernelCacheImage* BNKernelCacheControllerGetLoadedImages(BNKernelCacheController* controller, size_t* count)
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
		BNKernelCacheImage* apiImages = new BNKernelCacheImage[*count];
		for (size_t i = 0; i < *count; i++)
			apiImages[i] = ImageToApi(loadedImages[i]);
		return apiImages;
	}

	void BNKernelCacheFreeImage(BNKernelCacheImage image)
	{
		BNFreeString(image.name);
	}

	void BNKernelCacheFreeImageList(BNKernelCacheImage* images, size_t count)
	{
		for (size_t i = 0; i < count; i++)
			BNKernelCacheFreeImage(images[i]);
		delete[] images;
	}

	bool BNKernelCacheControllerGetSymbolAt(
		BNKernelCacheController* controller, uint64_t address, BNKernelCacheSymbol* outSymbol)
	{
		const auto symbol = controller->object->GetCache().GetSymbolAt(address);
		if (!symbol)
			return false;
		*outSymbol = SymbolToApi(*symbol);
		return true;
	}

	bool BNKernelCacheControllerGetSymbolWithName(
		BNKernelCacheController* controller, const char* name, BNKernelCacheSymbol* outSymbol)
	{
		const auto symbol = controller->object->GetCache().GetSymbolWithName(name);
		if (!symbol)
			return false;
		*outSymbol = SymbolToApi(*symbol);
		return true;
	}

	BNKernelCacheSymbol* BNKernelCacheControllerGetSymbols(BNKernelCacheController* controller, size_t* count)
	{
		const auto& symbols = controller->object->GetCache().GetSymbols();
		*count = symbols.size();
		BNKernelCacheSymbol* apiSymbols = new BNKernelCacheSymbol[*count];
		size_t idx = 0;
		for (const auto& [_, symbol] : symbols)
			apiSymbols[idx++] = SymbolToApi(symbol);
		return apiSymbols;
	}


	void BNKernelCacheFreeSymbol(BNKernelCacheSymbol symbol)
	{
		BNFreeString(symbol.name);
	}

	void BNKernelCacheFreeSymbolList(BNKernelCacheSymbol* symbols, size_t count)
	{
		for (size_t i = 0; i < count; i++)
			BNKernelCacheFreeSymbol(symbols[i]);
		delete[] symbols;
	}
};
