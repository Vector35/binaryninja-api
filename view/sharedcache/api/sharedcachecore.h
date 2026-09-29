#pragma once

#include "binaryninjacore.h"

#ifdef __GNUC__
	#ifdef SHAREDCACHE_LIBRARY
		#define SHAREDCACHE_FFI_API __attribute__((visibility("default")))
	#else  // SHAREDCACHE_LIBRARY
		#define SHAREDCACHE_FFI_API
	#endif  // SHAREDCACHE_LIBRARY
#else       // __GNUC__
	#ifdef _MSC_VER
		#ifndef DEMO_EDITION
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

	typedef struct BNSharedCacheController BNSharedCacheController;
	typedef struct BNSharedCacheStringScanner BNSharedCacheStringScanner;

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
		BNSymbolBinding symbolBinding;
		uint64_t address;
		char* name;
	} BNSharedCacheSymbol;

	typedef struct BNSharedCacheString {
		BNStringType stringType;
		uint64_t address;
		// Length of the string in the cache, in bytes.
		size_t rawLength;
		// UTF-8 display text, truncated.
		char* text;
		uint64_t regionStart;
		// NOTE: If not associated with an image this will be zero.
		uint64_t imageStart;
	} BNSharedCacheString;

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

	SHAREDCACHE_FFI_API BNSharedCacheStringScanner* BNSharedCacheControllerCreateStringScanner(
		BNSharedCacheController* controller);
	SHAREDCACHE_FFI_API void BNFreeSharedCacheStringScanner(BNSharedCacheStringScanner* scanner);
	SHAREDCACHE_FFI_API bool BNSharedCacheStringScannerStart(BNSharedCacheStringScanner* scanner);
	SHAREDCACHE_FFI_API bool BNSharedCacheStringScannerIsComplete(BNSharedCacheStringScanner* scanner);
	SHAREDCACHE_FFI_API void BNSharedCacheStringScannerGetProgress(
		BNSharedCacheStringScanner* scanner, uint64_t* current, uint64_t* total);

	SHAREDCACHE_FFI_API uint64_t BNSharedCacheStringScannerGetStringCount(BNSharedCacheStringScanner* scanner);
	// Removes and returns up to maxCount of the queued scan results.
	SHAREDCACHE_FFI_API BNSharedCacheString* BNSharedCacheStringScannerTakeStrings(
		BNSharedCacheStringScanner* scanner, uint64_t maxCount, size_t* count);

	SHAREDCACHE_FFI_API void BNSharedCacheFreeString(BNSharedCacheString string);
	SHAREDCACHE_FFI_API void BNSharedCacheFreeStringList(BNSharedCacheString* strings, size_t count);


#ifdef __cplusplus
}
#endif
