#pragma once


#ifdef __cplusplus
extern "C"
{
#endif

#ifdef __GNUC__
	#ifdef SHAREDCACHE_LIBRARY
		#define SHAREDCACHE_FFI_API __attribute__((visibility("default")))
	#else  // SHAREDCACHE_LIBRARY
		#define SHAREDCACHE_FFI_API
	#endif  // SHAREDCACHE_LIBRARY
#else       // __GNUC__
	#ifdef _MSC_VER
		#ifndef DEMO_VERSION
			#ifdef SHAREDCACHE_LIBRARY
				#define SHAREDCACHE_FFI_API __declspec(dllexport)
			#else  // SHAREDCACHE_LIBRARY
				#define SHAREDCACHE_FFI_API __declspec(dllimport)
			#endif  // SHAREDCACHE_LIBRARY
		#else
			#define SHAREDCACHE_FFI_API
		#endif
	#else  // _MSC_VER
		#define SHAREDCACHE_FFI_API
	#endif  // _MSC_VER
#endif      // __GNUC__C

#define CORE_ALLOCATED_STRUCT(T)

#define CORE_ALLOCATED_CLASS(T) \
	public: \
		CORE_ALLOCATED_STRUCT(T) \
	private:

#define DECLARE_SHAREDCACHE_API_OBJECT_INTERNAL(handle, cls, ns) \
	namespace ns { class cls; } struct handle { ns::cls* object; }

#define DECLARE_SHAREDCACHE_API_OBJECT(handle, cls) DECLARE_SHAREDCACHE_API_OBJECT_INTERNAL(handle, cls, SharedCacheCore)

#define IMPLEMENT_SHAREDCACHE_API_OBJECT(handle) \
		CORE_ALLOCATED_CLASS(handle) \
	private: \
		handle m_apiObject; \
	public: \
		typedef handle* APIHandle; \
		handle* GetAPIObject() { return &m_apiObject; } \
	private:
#define INIT_SHAREDCACHE_API_OBJECT() \
	m_apiObject.object = this;

	typedef enum BNDSCViewState {
		Unloaded,
		Loaded,
		LoadedWithImages,
	} BNDSCViewState;

	typedef enum BNDSCViewLoadProgress {
		LoadProgressNotStarted,
		LoadProgressLoadingCaches,
		LoadProgressLoadingImages,
		LoadProgressFinished,
	} BNDSCViewLoadProgress;

	typedef enum BNBackingCacheType {
		BackingCacheTypePrimary,
		BackingCacheTypeSecondary,
		BackingCacheTypeSymbols,
	} BNBackingCacheType;

	typedef struct BNBinaryView BNBinaryView;
	typedef struct BNSharedCache BNSharedCache;
	typedef struct BNStringRef BNStringRef;

	typedef struct BNDSCImageMemoryMapping {
		char* filePath;
		char* name;
		uint64_t vmAddress;
		uint64_t size;
		bool loaded;
		uint64_t rawViewOffset;
	} BNDSCImageMemoryMapping;

	typedef struct BNDSCImage {
		char* name;
		uint64_t headerAddress;
		BNDSCImageMemoryMapping* mappings;
		size_t mappingCount;
	} BNDSCImage;

	typedef struct BNDSCMappedMemoryRegion {
		uint64_t vmAddress;
		uint64_t size;
		char* name;
	} BNDSCMappedMemoryRegion;

	typedef struct BNDSCBackingCacheMapping {
		uint64_t vmAddress;
		uint64_t size;
		uint64_t fileOffset;
	} BNDSCBackingCacheMapping;

	typedef struct BNDSCBackingCache {
		char* path;
		BNBackingCacheType cacheType;
		BNDSCBackingCacheMapping* mappings;
		size_t mappingCount;
	} BNDSCBackingCache;

	typedef struct BNDSCMemoryUsageInfo {
		uint64_t sharedCacheRefs;
		uint64_t mmapRefs;
	} BNDSCMemoryUsageInfo;

	typedef struct BNDSCSymbolRep {
		uint64_t address;
		BNStringRef* name;
		char* image;
	} BNDSCSymbolRep;

	SHAREDCACHE_FFI_API BNSharedCache* BNGetSharedCache(BNBinaryView* data);

	SHAREDCACHE_FFI_API BNSharedCache* BNNewSharedCacheReference(BNSharedCache* cache);
	SHAREDCACHE_FFI_API void BNFreeSharedCacheReference(BNSharedCache* cache);

	SHAREDCACHE_FFI_API char** BNDSCViewGetInstallNames(BNSharedCache* cache, size_t* count);

	SHAREDCACHE_FFI_API bool BNDSCViewLoadImageWithInstallName(BNSharedCache* cache, char* name, bool skipObjC);
	SHAREDCACHE_FFI_API bool BNDSCViewLoadSectionAtAddress(BNSharedCache* cache, uint64_t name);
	SHAREDCACHE_FFI_API bool BNDSCViewLoadImageContainingAddress(BNSharedCache* cache, uint64_t address, bool skipObjC);
	
	SHAREDCACHE_FFI_API void BNDSCViewProcessObjCSectionsForImageWithInstallName(BNSharedCache* cache, char* name, bool deallocName);
	SHAREDCACHE_FFI_API void BNDSCViewProcessAllObjCSections(BNSharedCache* cache);

	SHAREDCACHE_FFI_API char* BNDSCViewGetNameForAddress(BNSharedCache* cache, uint64_t address);
	SHAREDCACHE_FFI_API char* BNDSCViewGetImageNameForAddress(BNSharedCache* cache, uint64_t address);

	SHAREDCACHE_FFI_API BNDSCViewState BNDSCViewGetState(BNSharedCache* cache);
	SHAREDCACHE_FFI_API BNDSCViewLoadProgress BNDSCViewGetLoadProgress(uint64_t sessionID);
	SHAREDCACHE_FFI_API uint64_t BNDSCViewFastGetBackingCacheCount(BNBinaryView* view);

	SHAREDCACHE_FFI_API BNDSCSymbolRep* BNDSCViewLoadAllSymbolsAndWait(BNSharedCache* cache, size_t* count);
	SHAREDCACHE_FFI_API void BNDSCViewFreeSymbols(BNDSCSymbolRep* symbols, size_t count);

	SHAREDCACHE_FFI_API BNDSCMappedMemoryRegion* BNDSCViewGetLoadedRegions(BNSharedCache* cache, size_t* count);
	SHAREDCACHE_FFI_API void BNDSCViewFreeLoadedRegions(BNDSCMappedMemoryRegion* images, size_t count);

	SHAREDCACHE_FFI_API BNDSCImage* BNDSCViewGetAllImages(BNSharedCache* cache, size_t* count);
	SHAREDCACHE_FFI_API void BNDSCViewFreeAllImages(BNDSCImage* images, size_t count);

	SHAREDCACHE_FFI_API BNDSCBackingCache* BNDSCViewGetBackingCaches(BNSharedCache* cache, size_t* count);
	SHAREDCACHE_FFI_API void BNDSCViewFreeBackingCaches(BNDSCBackingCache* caches, size_t count);

	SHAREDCACHE_FFI_API void BNDSCFindSymbolAtAddressAndApplyToAddress(BNSharedCache* cache, uint64_t symbolLocation, uint64_t targetLocation, bool triggerReanalysis);

	SHAREDCACHE_FFI_API char* BNDSCViewGetImageHeaderForAddress(BNSharedCache* cache, uint64_t address);
	SHAREDCACHE_FFI_API char* BNDSCViewGetImageHeaderForName(BNSharedCache* cache, char* name);

	[[maybe_unused]] SHAREDCACHE_FFI_API BNDSCMemoryUsageInfo BNDSCViewGetMemoryUsageInfo();

#ifdef __cplusplus
}
#endif
