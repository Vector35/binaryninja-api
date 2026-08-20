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
		#ifndef DEMO_EDITION
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

#define CORE_ALLOCATED_STRUCT(T)

#define CORE_ALLOCATED_CLASS(T) \
	public: \
		CORE_ALLOCATED_STRUCT(T) \
	private:

	typedef struct BNBinaryView BNBinaryView;
	typedef struct BNKernelCacheController BNKernelCacheController;

	typedef enum BNKernelCacheEntryType {
		KernelCacheEntryTypePrimary,
		KernelCacheEntryTypeSecondary,
		KernelCacheEntryTypeSymbols,
		KernelCacheEntryTypeDyldData,
		KernelCacheEntryTypeStub,
	} BNKernelCacheEntryType;

	typedef enum BNKernelCacheRegionType {
		KernelCacheRegionTypeImage,
		KernelCacheRegionTypeStubIsland,
		KernelCacheRegionTypeDyldData,
		KernelCacheRegionTypeNonImage,
	} BNKernelCacheRegionType;

	typedef struct BNKernelCacheImage {
		char* name;
		uint64_t headerVirtualAddress;
		uint64_t headerFileAddress;
	} BNKernelCacheImage;

	typedef struct BNKernelCacheRegion {
		BNKernelCacheRegionType regionType;
		char* name;
		uint64_t vmAddress;
		uint64_t size;
		// NOTE: If not associated with an image this will be zero.
		uint64_t imageStart;
		BNSegmentFlag flags;
	} BNKernelCacheRegion;

	typedef struct BNKernelCacheMappingInfo {
		uint64_t vmAddress;
		uint64_t size;
		uint64_t fileOffset;
	} BNKernelCacheMappingInfo;

	typedef struct BNKernelCacheSymbol {
		BNSymbolType symbolType;
		uint64_t address;
		char* name;
	} BNKernelCacheSymbol;

	KERNELCACHE_FFI_API BNKernelCacheController* BNGetKernelCacheController(BNBinaryView* data);

	KERNELCACHE_FFI_API BNKernelCacheController* BNNewKernelCacheControllerReference(BNKernelCacheController* controller);
	KERNELCACHE_FFI_API void BNFreeKernelCacheControllerReference(BNKernelCacheController* controller);

	KERNELCACHE_FFI_API bool BNKernelCacheControllerApplyImage(BNKernelCacheController* controller, BNBinaryView* view, BNKernelCacheImage* image);

	KERNELCACHE_FFI_API bool BNKernelCacheControllerIsImageLoaded(BNKernelCacheController* controller, BNKernelCacheImage* image);

	KERNELCACHE_FFI_API bool BNKernelCacheControllerGetImageAt(BNKernelCacheController* controller, uint64_t address, BNKernelCacheImage* image);
	KERNELCACHE_FFI_API bool BNKernelCacheControllerGetImageContaining(BNKernelCacheController* controller, uint64_t address, BNKernelCacheImage* image);
	KERNELCACHE_FFI_API bool BNKernelCacheControllerGetImageWithName(BNKernelCacheController* controller, const char* name, BNKernelCacheImage* image);

	KERNELCACHE_FFI_API char** BNKernelCacheControllerGetImageDependencies(BNKernelCacheController* controller, BNKernelCacheImage* image, size_t* count);

	KERNELCACHE_FFI_API BNKernelCacheImage* BNKernelCacheControllerGetImages(BNKernelCacheController* controller, size_t* count);
	KERNELCACHE_FFI_API BNKernelCacheImage* BNKernelCacheControllerGetLoadedImages(BNKernelCacheController* controller, size_t* count);

	KERNELCACHE_FFI_API void BNKernelCacheFreeImage(BNKernelCacheImage image);
	KERNELCACHE_FFI_API void BNKernelCacheFreeImageList(BNKernelCacheImage* images, size_t count);

	KERNELCACHE_FFI_API bool BNKernelCacheControllerGetSymbolAt(BNKernelCacheController* controller, uint64_t address, BNKernelCacheSymbol* symbol);
	KERNELCACHE_FFI_API bool BNKernelCacheControllerGetSymbolWithName(BNKernelCacheController* controller, const char* name, BNKernelCacheSymbol* symbol);

	KERNELCACHE_FFI_API BNKernelCacheSymbol* BNKernelCacheControllerGetSymbols(BNKernelCacheController* controller, size_t* count);

	KERNELCACHE_FFI_API void BNKernelCacheFreeSymbol(BNKernelCacheSymbol symbol);
	KERNELCACHE_FFI_API void BNKernelCacheFreeSymbolList(BNKernelCacheSymbol* symbols, size_t count);
#ifdef __cplusplus
}
#endif
