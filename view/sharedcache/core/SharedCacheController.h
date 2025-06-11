#pragma once

#include <regex>

#include "SharedCache.h"
#include "refcountobject.h"
#include "ffi_global.h"

DECLARE_DSC_API_OBJECT(BNSharedCacheController, SharedCacheController);

void RegisterSharedCacheControllerDestructor();

namespace BinaryNinja::DSC {
	static const char* METADATA_KEY = "shared_cache";
	static const char* OLD_METADATA_KEY_COUNT = "SHAREDCACHE-ModifiedState-Count";
	static const char* OLD_METADATA_KEY_PREFIX = "SHAREDCACHE-ModifiedState-";

	// Represents the view state for a given `DSCache`
	class SharedCacheController : public DSCRefCountObject
	{
		IMPLEMENT_DSC_API_OBJECT(BNSharedCacheController);
		Ref<Logger> m_logger;
		SharedCache m_cache;

		// Locks on load attempts (region or image).
		std::shared_mutex m_loadMutex;

		// Store the open images.
		// Things other than the cache here will be serialized.
		std::unordered_set<uint64_t> m_loadedRegions;
		std::unordered_set<uint64_t> m_loadedImages;

		// Settings from the view.
		std::regex m_regionFilter;
		bool m_processObjC;
		bool m_processCFStrings;

		explicit SharedCacheController(SharedCache&& cache, Ref<Logger> logger);

	public:
		// Initialize the DSCacheView, this should be called from the view initialize function only!
		static DSCRef<SharedCacheController> Initialize(BinaryView& view, SharedCache&& cache);

		// NOTE: This will not create one if it does not exist. To create one for the view call `Initialize`.
		static DSCRef<SharedCacheController> FromView(const BinaryView& view);

		SharedCache& GetCache() { return m_cache; };
		const std::unordered_set<uint64_t>& GetLoadedRegions() { return m_loadedRegions; };
		const std::unordered_set<uint64_t>& GetLoadedImages() { return m_loadedImages; };

		// TODO: LoadResult type? AlreadyLoaded, Loaded, NotLoaded.
		// NOTE: `address` should be the start of a region, not containing the address.
		bool ApplyRegionAtAddress(BinaryView& view, uint64_t address);

		bool ApplyRegion(BinaryView& view, const CacheRegion& region);

		bool IsRegionLoaded(const CacheRegion& region);

		// Loads the relevant image info into the view. This does not update analysis so if you
		// call this make sure at some point you update analysis and likely with linear sweep.
		bool ApplyImage(BinaryView& view, const CacheImage& image);

		bool IsImageLoaded(const CacheImage& image);

		// Get the metadata for saving the state of the shared cache.
		Ref<Metadata> GetMetadata() const;

		void LoadMetadata(const Metadata& metadata);
	};
}  // namespace BinaryNinja::DSC
