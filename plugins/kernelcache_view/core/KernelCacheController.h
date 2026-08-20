#pragma once

#include <regex>

#include <shared_mutex>
#include "KernelCache.h"
#include "refcountobject.h"
#include "ffi_global.h"

DECLARE_KC_API_OBJECT(BNKernelCacheController, KernelCacheController);

void RegisterKernelCacheControllerDestructor();

namespace BinaryNinja::KC {
	// Represents the view state for a given `DSCache`
	class KernelCacheController : public KCRefCountObject
	{
		IMPLEMENT_KC_API_OBJECT(BNKernelCacheController);
		Ref<Logger> m_logger;
		KernelCache m_cache;

		// Locks on load attempts (region or image).
		std::shared_mutex m_loadMutex;

		// Store the open images.
		std::unordered_set<uint64_t> m_loadedImages;

		// Settings from the view.
		std::regex m_regionFilter;

		explicit KernelCacheController(KernelCache&& cache, Ref<Logger> logger);

	public:
		// Initialize the DSCacheView, this should be called from the view initialize function only!
		static KCRef<KernelCacheController> Initialize(BinaryView& view, KernelCache&& cache);

		// NOTE: This will not create one if it does not exist. To create one for the view call `Initialize`.
		static KCRef<KernelCacheController> FromView(const BinaryView& view);

		KernelCache& GetCache() { return m_cache; };
		const std::unordered_set<uint64_t>& GetLoadedImages() { return m_loadedImages; };

		// Loads the relevant image info into the view. This does not update analysis so if you
		// call this make sure at some point you update analysis and likely with linear sweep.
		bool ApplyImage(BinaryView& view, const CacheImage& image);

		bool IsImageLoaded(const CacheImage& image);
	};
}  // namespace BinaryNinja::KC
