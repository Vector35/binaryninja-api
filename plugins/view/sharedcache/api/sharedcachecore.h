#pragma once

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

#ifdef __cplusplus
extern "C"
{
#endif

	//	binaryninjacore.h is not included so we must duplicate enum types here.
#ifdef BN_TYPE_PARSER
	typedef enum BNSegmentFlag
	{
		SegmentExecutable = 1,
		SegmentWritable = 2,
		SegmentReadable = 4,
		SegmentContainsData = 8,
		SegmentContainsCode = 0x10,
		SegmentDenyWrite = 0x20,
		SegmentDenyExecute = 0x40
	} BNSegmentFlag;

	typedef enum BNSymbolType
	{
		FunctionSymbol = 0,
		ImportAddressSymbol = 1,
		ImportedFunctionSymbol = 2,
		DataSymbol = 3,
		ImportedDataSymbol = 4,
		ExternalSymbol = 5,
		LibraryFunctionSymbol = 6,
		SymbolicFunctionSymbol = 7,
		LocalLabelSymbol = 8,
	} BNSymbolType;
#endif

	typedef struct BNBinaryView BNBinaryView;
	typedef struct BNSharedCacheController BNSharedCacheController;

	typedef enum BNSharedCacheEntryType {
		SharedCacheEntryTypePrimary,
		SharedCacheEntryTypeSecondary,
		SharedCacheEntryTypeSymbols,
		SharedCacheEntryTypeDyldData,
		SharedCacheEntryTypeStub,
	} BNSharedCacheEntryType;

	typedef enum BNSharedCacheRegionType {
		SharedCacheRegionTypeImage,
		SharedCacheRegionTypeStubIsland,
		SharedCacheRegionTypeDyldData,
		SharedCacheRegionTypeNonImage,
	} BNSharedCacheRegionType;

	typedef struct BNSharedCacheImage {
		char* name;
		uint64_t headerAddress;
		size_t regionStartCount;
		uint64_t* regionStarts;
	} BNSharedCacheImage;

	typedef struct BNSharedCacheRegion {
		BNSharedCacheRegionType regionType;
		char* name;
		uint64_t vmAddress;
		uint64_t size;
		// NOTE: If not associated with an image this will be zero.
		uint64_t imageStart;
		BNSegmentFlag flags;
	} BNSharedCacheRegion;

	typedef struct BNSharedCacheMappingInfo {
		uint64_t vmAddress;
		uint64_t size;
		uint64_t fileOffset;
	} BNSharedCacheMappingInfo;

	typedef struct BNSharedCacheEntry {
		char* path;
		char* name;
		BNSharedCacheEntryType entryType;
		size_t mappingCount;
		BNSharedCacheMappingInfo* mappings;
	} BNSharedCacheEntry;

	typedef struct BNSharedCacheSymbol {
		BNSymbolType symbolType;
		uint64_t address;
		char* name;
	} BNSharedCacheSymbol;

	SHAREDCACHE_FFI_API BNSharedCacheController* BNGetSharedCacheController(BNBinaryView* data);

	SHAREDCACHE_FFI_API BNSharedCacheController* BNNewSharedCacheControllerReference(BNSharedCacheController* controller);
	SHAREDCACHE_FFI_API void BNFreeSharedCacheControllerReference(BNSharedCacheController* controller);

	SHAREDCACHE_FFI_API bool BNSharedCacheControllerApplyImage(BNSharedCacheController* controller, BNBinaryView* view, BNSharedCacheImage* image);
	SHAREDCACHE_FFI_API bool BNSharedCacheControllerApplyRegion(BNSharedCacheController* controller, BNBinaryView* view, BNSharedCacheRegion* region);

	SHAREDCACHE_FFI_API bool BNSharedCacheControllerIsImageLoaded(BNSharedCacheController* controller, BNSharedCacheImage* image);
	SHAREDCACHE_FFI_API bool BNSharedCacheControllerIsRegionLoaded(BNSharedCacheController* controller, BNSharedCacheRegion* region);
	
	SHAREDCACHE_FFI_API bool BNSharedCacheControllerGetRegionAt(BNSharedCacheController* controller, uint64_t address, BNSharedCacheRegion* outRegion);
	SHAREDCACHE_FFI_API bool BNSharedCacheControllerGetRegionContaining(BNSharedCacheController* controller, uint64_t address, BNSharedCacheRegion* region);

	SHAREDCACHE_FFI_API BNSharedCacheRegion* BNSharedCacheControllerGetRegions(BNSharedCacheController* controller, size_t* count);
	SHAREDCACHE_FFI_API BNSharedCacheRegion* BNSharedCacheControllerGetLoadedRegions(BNSharedCacheController* controller, size_t* count);

	SHAREDCACHE_FFI_API uint64_t* BNSharedCacheAllocRegionList(uint64_t* list, size_t count);

	SHAREDCACHE_FFI_API void BNSharedCacheFreeRegion(BNSharedCacheRegion region);
	SHAREDCACHE_FFI_API void BNSharedCacheFreeRegionList(BNSharedCacheRegion* regions, size_t count);

	SHAREDCACHE_FFI_API bool BNSharedCacheControllerGetImageAt(BNSharedCacheController* controller, uint64_t address, BNSharedCacheImage* image);
	SHAREDCACHE_FFI_API bool BNSharedCacheControllerGetImageContaining(BNSharedCacheController* controller, uint64_t address, BNSharedCacheImage* image);
	SHAREDCACHE_FFI_API bool BNSharedCacheControllerGetImageWithName(BNSharedCacheController* controller, const char* name, BNSharedCacheImage* image);

	SHAREDCACHE_FFI_API char** BNSharedCacheControllerGetImageDependencies(BNSharedCacheController* controller, BNSharedCacheImage* image, size_t* count);

	SHAREDCACHE_FFI_API BNSharedCacheImage* BNSharedCacheControllerGetImages(BNSharedCacheController* controller, size_t* count);
	SHAREDCACHE_FFI_API BNSharedCacheImage* BNSharedCacheControllerGetLoadedImages(BNSharedCacheController* controller, size_t* count);

	SHAREDCACHE_FFI_API void BNSharedCacheFreeImage(BNSharedCacheImage image);
	SHAREDCACHE_FFI_API void BNSharedCacheFreeImageList(BNSharedCacheImage* images, size_t count);

	SHAREDCACHE_FFI_API bool BNSharedCacheControllerGetSymbolAt(BNSharedCacheController* controller, uint64_t address, BNSharedCacheSymbol* symbol);
	SHAREDCACHE_FFI_API bool BNSharedCacheControllerGetSymbolWithName(BNSharedCacheController* controller, const char* name, BNSharedCacheSymbol* symbol);

	SHAREDCACHE_FFI_API BNSharedCacheSymbol* BNSharedCacheControllerGetSymbols(BNSharedCacheController* controller, size_t* count);

	SHAREDCACHE_FFI_API void BNSharedCacheFreeSymbol(BNSharedCacheSymbol symbol);
	SHAREDCACHE_FFI_API void BNSharedCacheFreeSymbolList(BNSharedCacheSymbol* symbols, size_t count);

	SHAREDCACHE_FFI_API BNSharedCacheEntry* BNSharedCacheControllerGetEntries(BNSharedCacheController* controller, size_t* count);

	SHAREDCACHE_FFI_API void BNSharedCacheFreeEntry(BNSharedCacheEntry entry);
	SHAREDCACHE_FFI_API void BNSharedCacheFreeEntryList(BNSharedCacheEntry* entries, size_t count);


#ifdef __cplusplus
}
#endif
