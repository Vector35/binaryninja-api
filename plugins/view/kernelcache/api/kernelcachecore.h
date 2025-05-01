#pragma once


#ifdef __cplusplus
extern "C"
{
#endif

#ifdef __GNUC__
	#ifdef KERNELCACHE_LIBRARY
		#define KERNELCACHE_FFI_API __attribute__((visibility("default")))
	#else  // KERNELCACHE_LIBRARY
		#define KERNELCACHE_FFI_API
	#endif  // KERNELCACHE_LIBRARY
#else       // __GNUC__
	#ifdef _MSC_VER
		#ifndef DEMO_VERSION
			#ifdef KERNELCACHE_LIBRARY
				#define KERNELCACHE_FFI_API __declspec(dllexport)
			#else  // KERNELCACHE_LIBRARY
				#define KERNELCACHE_FFI_API __declspec(dllimport)
			#endif  // KERNELCACHE_LIBRARY
		#else
			#define KERNELCACHE_FFI_API
		#endif
	#else  // _MSC_VER
		#define KERNELCACHE_FFI_API
	#endif  // _MSC_VER
#endif      // __GNUC__C

#define CORE_ALLOCATED_STRUCT(T)

#define CORE_ALLOCATED_CLASS(T) \
	public: \
		CORE_ALLOCATED_STRUCT(T) \
	private:

#define DECLARE_KERNELCACHE_API_OBJECT_INTERNAL(handle, cls, ns) \
	namespace ns { class cls; } struct handle { ns::cls* object; }

#define DECLARE_KERNELCACHE_API_OBJECT(handle, cls) DECLARE_KERNELCACHE_API_OBJECT_INTERNAL(handle, cls, KernelCacheCore)

#define IMPLEMENT_KERNELCACHE_API_OBJECT(handle) \
		CORE_ALLOCATED_CLASS(handle) \
	private: \
		handle m_apiObject; \
	public: \
		typedef handle* APIHandle; \
		handle* GetAPIObject() { return &m_apiObject; } \
	private:
#define INIT_KERNELCACHE_API_OBJECT() \
	m_apiObject.object = this;

	typedef enum BNKCViewState {
		Unloaded,
		Loaded,
		LoadedWithImages,
	} BNKCViewState;

	typedef enum BNKCViewLoadProgress {
		LoadProgressNotStarted,
		LoadProgressLoadingCaches,
		LoadProgressLoadingImages,
		LoadProgressFinished,
	} BNKCViewLoadProgress;

	typedef struct BNBinaryView BNBinaryView;
	typedef struct BNKernelCache BNKernelCache;

	typedef struct BNKCImageMemoryMapping {
		char* name;
		uint64_t vmAddress;
		uint64_t size;
		bool loaded;
		uint64_t rawViewOffset;
	} BNKCImageMemoryMapping;

	typedef struct BNKCImage {
		char* name;
		uint64_t headerFileAddress;
		BNKCImageMemoryMapping* mappings;
		size_t mappingCount;
	} BNKCImage;

	typedef struct BNKCMappedMemoryRegion {
		uint64_t vmAddress;
		uint64_t size;
		char* name;
	} BNKCMappedMemoryRegion;

	typedef struct BNKCMemoryUsageInfo {
		uint64_t sharedCacheRefs;
		uint64_t mmapRefs;
	} BNKCMemoryUsageInfo;

	typedef struct BNKCSymbolRep {
		uint64_t address;
		char* name;
		char* image;
	} BNKCSymbolRep;

	KERNELCACHE_FFI_API BNKernelCache* BNGetKernelCache(BNBinaryView* data);

	KERNELCACHE_FFI_API BNKernelCache* BNNewKernelCacheReference(BNKernelCache* cache);
	KERNELCACHE_FFI_API void BNFreeKernelCacheReference(BNKernelCache* cache);

	KERNELCACHE_FFI_API char** BNKCViewGetInstallNames(BNKernelCache* cache, size_t* count);

	KERNELCACHE_FFI_API bool BNKCViewLoadImageWithInstallName(BNKernelCache* cache, char* name);
	KERNELCACHE_FFI_API bool BNKCViewLoadImageContainingAddress(BNKernelCache* cache, uint64_t address);

	KERNELCACHE_FFI_API bool BNKCViewIsImageLoaded(BNKernelCache* cache, uint64_t address);

	KERNELCACHE_FFI_API char* BNKCViewGetNameForAddress(BNKernelCache* cache, uint64_t address);
	KERNELCACHE_FFI_API char* BNKCViewGetImageNameForAddress(BNKernelCache* cache, uint64_t address);

	KERNELCACHE_FFI_API BNKCViewState BNKCViewGetState(BNKernelCache* cache);
	KERNELCACHE_FFI_API BNKCViewLoadProgress BNKCViewGetLoadProgress(uint64_t sessionID);
	KERNELCACHE_FFI_API uint64_t BNKCViewFastGetImageCount(BNBinaryView* view);

	KERNELCACHE_FFI_API BNKCSymbolRep* BNKCViewLoadAllSymbolsAndWait(BNKernelCache* cache, size_t* count);
	KERNELCACHE_FFI_API void BNKCViewFreeSymbols(BNKCSymbolRep* symbols, size_t count);

	KERNELCACHE_FFI_API BNKCImage* BNKCViewGetAllImages(BNKernelCache* cache, size_t* count);
	KERNELCACHE_FFI_API void BNKCViewFreeAllImages(BNKCImage* images, size_t count);

	KERNELCACHE_FFI_API BNKCImage* BNKCViewGetLoadedImages(BNKernelCache* cache, size_t* count);
	KERNELCACHE_FFI_API void BNKCViewFreeLoadedImages(BNKCImage* images, size_t count);

	KERNELCACHE_FFI_API char* BNKCViewGetImageHeaderForAddress(BNKernelCache* cache, uint64_t address);
	KERNELCACHE_FFI_API char* BNKCViewGetImageHeaderForName(BNKernelCache* cache, char* name);

#ifdef __cplusplus
}
#endif
