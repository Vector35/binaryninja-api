#include "KernelCacheController.h"
#include "MachOProcessor.h"

using namespace BinaryNinja;
using namespace BinaryNinja::KC;

typedef uint64_t ViewId;

std::shared_mutex GlobalControllersMutex;

std::map<ViewId, KCRef<KernelCacheController>>& GlobalControllers()
{
	static std::map<ViewId, KCRef<KernelCacheController>> g_controllers = {};
	return g_controllers;
}


ViewId GetViewIdFromFileMetadata(const FileMetadata& file)
{
	// Currently the view id is just the views session id.
	// NOTE: If we want more than one shared cache controller per view we would need to make this more unique.
	return file.GetSessionId();
}

void DeleteController(const FileMetadata& file)
{
	const auto id = GetViewIdFromFileMetadata(file);
	std::unique_lock<std::shared_mutex> lock(GlobalControllersMutex);
	auto& controllers = GlobalControllers();
	if (auto it = controllers.find(id); it != controllers.end())
	{
		auto controller = it->second;
		// Someone is still holding the controller, lets warn about this.
		// 2 is expected here because we have one held in `controllers` and one held by `controller`.
		if (controller->m_refs > 2)
			LogWarnF("Deleting KernelCacheController for view {:#x}, but there are still {} references", id,
				controller->m_refs.load());

		controllers.erase(it);
		LogDebugF("Deleted KernelCacheController for view {:?}", file.GetFilename());
	}
}

void RegisterKernelCacheControllerDestructor()
{
	BNObjectDestructionCallbacks callbacks = {};
	callbacks.destructFileMetadata = [](void* ctx, BNFileMetadata* obj) -> void {
		const auto file = FileMetadata(obj);
		DeleteController(file);
	};
	BNRegisterObjectDestructionCallbacks(&callbacks);
}

KernelCacheController::KernelCacheController(KernelCache&& cache, Ref<Logger> logger) : m_cache(std::move(cache))
{
	INIT_KC_API_OBJECT();
	m_logger = std::move(logger);
	m_loadedImages = {};
	m_regionFilter = std::regex(".*LINKEDIT.*");
}

KCRef<KernelCacheController> KernelCacheController::Initialize(BinaryView& view, KernelCache&& cache)
{
	auto id = GetViewIdFromFileMetadata(*view.GetFile());
	std::unique_lock<std::shared_mutex> lock(GlobalControllersMutex);
	auto logger = new Logger("KernelCache.Controller", view.GetFile()->GetSessionId());
	KCRef<KernelCacheController> controller = new KernelCacheController(std::move(cache), logger);

	// Pull the settings from the view.
	if (Ref<Settings> settings = view.GetLoadSettings(KC_VIEW_NAME))
	{
		if (settings->Contains("loader.kc.regionFilter"))
			controller->m_regionFilter = std::regex(settings->Get<std::string>("loader.kc.regionFilter", &view));
	}

	// TODO: Support old shared cache metadata
	// TODO: Not strictly necessary as the user has already loaded the information into the database, this would just
	// TODO: prevent incidental extra work from being done when loading a region or image.
	// const uint64_t oldStateCount = view.GetUIntMetadata(OLD_METADATA_KEY_COUNT);

	// Check the view auto metadata for shared cache information.
	// This effectively restores the state of the opened database to when it was last saved.
	// NOTE: We store on the parent view because hilariously, the metadata is not present until after view init.
	if (auto loadedImageMetadata = view.GetParentView()->QueryMetadata("KernelCacheLoadedImages"))
	{
		auto loadedImageList = loadedImageMetadata->GetArray();
		for (const auto & imageAddrMeta : loadedImageList)
		{
			auto imageAddr = imageAddrMeta->GetUnsignedInteger();
			controller->m_loadedImages.insert(imageAddr);
		}
	}

	GlobalControllers().insert({id, controller});
	return controller;
}

KCRef<KernelCacheController> KernelCacheController::FromView(const BinaryView& view)
{
	auto id = GetViewIdFromFileMetadata(*view.GetFile());
	std::shared_lock<std::shared_mutex> lock(GlobalControllersMutex);
	auto& dscViews = GlobalControllers();
	auto dscView = dscViews.find(id);
	if (dscView == dscViews.end())
		return nullptr;
	return dscView->second;
}

bool KernelCacheController::ApplyImage(BinaryView& view, const CacheImage& image)
{
	// Load all regions of an image and mark the image as loaded.
	// NOTE: The regions lock m_loadMutex themselves, so we do not hold it up here.
	bool loadedRegion = false;

	BNRelocationInfo reloc;
	memset(&reloc, 0, sizeof(BNRelocationInfo));
	reloc.type = StandardRelocationType;
	reloc.size = 8;
	reloc.nativeType = BINARYNINJA_MANUAL_RELOCATION;

	// We check for a valid offset as we apply auto segments and re-call this function on view init
	if (!view.IsValidOffset(image.headerVirtualAddress))
	{
		loadedRegion = true;
		auto memoryMap = view.GetMemoryMap();
		for (const auto& segment : image.header->segments)
		{
			if (segment.vmsize == 0)
				continue;

			auto flags = SegmentFlagsForSegment(segment);
			view.AddAutoSegment(segment.vmaddr, segment.vmsize, segment.fileoff, segment.filesize, flags);

			if (memoryMap)
			{
				std::string segmentName(segment.segname, std::find(segment.segname, std::end(segment.segname), '\0'));
				std::string displayName = image.GetName() + "::" + segmentName;

				auto region = memoryMap->GetActiveMemoryRegionAt(segment.vmaddr);
				if (!region.empty())
					memoryMap->SetMemoryRegionDisplayName(region, displayName);

				if (segment.vmsize != segment.filesize)
				{
					auto fillStart = segment.vmaddr + segment.filesize;
					auto fillRegion = memoryMap->GetActiveMemoryRegionAt(fillStart);

					if (!fillRegion.empty() && fillRegion != region)
						memoryMap->SetMemoryRegionDisplayName(fillRegion, displayName + " (zero fill)");
				}
			}

			const auto& relocations = m_cache.GetRelocations();

			auto begin = std::lower_bound(relocations.begin(), relocations.end(), segment.vmaddr,
				[](const std::pair<uint64_t, uint64_t>& reloc, uint64_t addr) {
					return reloc.first < addr;
				});

			auto arch = view.GetDefaultArchitecture();
			// Process relocations until the VM address is beyond our region
			for (auto it = begin; it != relocations.end() && it->first < segment.vmaddr + segment.vmsize; ++it) {
				reloc.address = it->first;
				view.DefineRelocation(arch, reloc, it->second, reloc.address);
			}
		}
	}

	view.FinalizeNewSegments();

	// The ApplyRegionAtAddress no longer holds the lock, we can take it now.
	std::unique_lock<std::shared_mutex> lock(m_loadMutex);


	// If there was no loaded regions than we just want to forgo loading the image.
	// We also skip if we already loaded the image itself. We do this after loading regions
	// as we regions have their own check.

	// On view init, we exit here as we just need to re-add the segments and relocations.
	if (!loadedRegion || m_loadedImages.find(image.headerVirtualAddress) != m_loadedImages.end())
		return false;

	if (image.headerVirtualAddress)
	{
		// Header information is applied to the view here, such as sections.
		auto machoProcessor = KernelCacheMachOProcessor(&view);

		// Adding a user section will mark all functions for updates unless we disable this.
		// Because images are known separate compilation units, we have a real reason to make sure we don't mark all previously
		// analyzed functions as updated.
		auto prevDisabledState = view.GetFunctionAnalysisUpdateDisabled();
		view.SetFunctionAnalysisUpdateDisabled(true);
		machoProcessor.ApplyHeader(GetCache(), *image.header);
		view.SetFunctionAnalysisUpdateDisabled(prevDisabledState);
	}

	m_loadedImages.insert(image.headerVirtualAddress);

	m_logger->LogInfoF("Loaded image: '{}'", image.path);

	// TODO: This needs to be done in a "database save" callback.
	// NOTE: We store on the parent view because hilariously, the view metadata is not available in view init.
	std::vector<uint64_t> loadedImages;
	loadedImages.reserve(m_loadedImages.size());
	// Store the loaded images in the metadata.
	for (const uint64_t& addr : m_loadedImages)
	{
		loadedImages.push_back(addr);
	}
	view.GetParentView()->StoreMetadata("KernelCacheLoadedImages", new Metadata(loadedImages));

	// TODO: Partial failure state (i.e. 2 regions loaded, one failed)
	return true;
}

bool KernelCacheController::IsImageLoaded(const CacheImage& image)
{
	std::shared_lock<std::shared_mutex> lock(m_loadMutex);
	return std::any_of(m_loadedImages.begin(), m_loadedImages.end(), [&](const auto& loadedImage) {
		return loadedImage == image.headerVirtualAddress;
	});
}
