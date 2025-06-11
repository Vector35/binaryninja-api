#pragma once

// These types will be parsed directly from the files.

#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
	#define PACKED_STRUCT __attribute__((packed))
#else
	#define PACKED_STRUCT
#endif

struct PACKED_STRUCT dyld_cache_mapping_info
{
	uint64_t address;
	uint64_t size;
	uint64_t fileOffset;
	uint32_t maxProt;
	uint32_t initProt;
};

struct dyld_cache_slide_info
{
	uint32_t version;
	uint32_t toc_offset;
	uint32_t toc_count;
	uint32_t entries_offset;
	uint32_t entries_count;
	uint32_t entries_size;
	// uint16_t toc[toc_count];
	// entrybitmap entries[entries_count];
};

struct dyld_cache_slide_info_entry
{
	uint8_t bits[4096 / (8 * 4)];  // 128-byte bitmap
};

struct PACKED_STRUCT dyld_cache_mapping_and_slide_info
{
	uint64_t address;
	uint64_t size;
	uint64_t fileOffset;
	uint64_t slideInfoFileOffset;
	uint64_t slideInfoFileSize;
	uint64_t flags;
	uint32_t maxProt;
	uint32_t initProt;
};

struct PACKED_STRUCT dyld_cache_slide_info_v2
{
	uint32_t version;
	uint32_t page_size;
	uint32_t page_starts_offset;
	uint32_t page_starts_count;
	uint32_t page_extras_offset;
	uint32_t page_extras_count;
	uint64_t delta_mask;
	uint64_t value_add;
};
#define DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA     0x8000  // index is into extras array (not starts array)
#define DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE 0x4000  // page has no rebasing
#define DYLD_CACHE_SLIDE_PAGE_ATTR_END       0x8000  // last chain entry for page

#define DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE 0xFFFF  // page has no rebasing

struct PACKED_STRUCT dyld_cache_slide_info_v3
{
	uint32_t version;
	uint32_t page_size;
	uint32_t page_starts_count;
	uint32_t pad_i_guess;
	uint64_t auth_value_add;
};


// DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE
struct dyld_chained_ptr_arm64e_shared_cache_rebase
{
	uint64_t runtimeOffset : 34,  // offset from the start of the shared cache
		high8 : 8, unused : 10,
		next : 11,  // 8-byte stide
		auth : 1;   // == 0
};

// DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE
struct dyld_chained_ptr_arm64e_shared_cache_auth_rebase
{
	uint64_t runtimeOffset : 34,  // offset from the start of the shared cache
		diversity : 16, addrDiv : 1,
		keyIsData : 1,  // implicitly always the 'A' key.  0 -> IA.  1 -> DA
		next : 11,      // 8-byte stide
		auth : 1;       // == 1
};

// TODO: dyld_cache_slide_info4 is used in watchOS which we are not close to supporting right now.

#define DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE 0xFFFF  // page has no rebasing

struct PACKED_STRUCT dyld_cache_slide_info_v5
{
	uint32_t version;    // currently 5
	uint32_t page_size;  // currently 4096 (may also be 16384)
	uint32_t page_starts_count;
	uint32_t pad;  // padding to ensure the value below is on an 8-byte boundary
	uint64_t value_add;
	// uint16_t    page_starts[/* page_starts_count */];
};


struct PACKED_STRUCT dyld_cache_image_info
{
	uint64_t address;
	uint64_t modTime;
	uint64_t inode;
	uint32_t pathFileOffset;
	uint32_t pad;

	bool operator==(const dyld_cache_image_info& image) const;
};

union dyld_cache_slide_pointer5
{
	uint64_t raw;
	struct dyld_chained_ptr_arm64e_shared_cache_rebase regular;
	struct dyld_chained_ptr_arm64e_shared_cache_auth_rebase auth;
};


struct PACKED_STRUCT dyld_cache_local_symbols_info
{
	uint32_t nlistOffset;    // offset into this chunk of nlist entries
	uint32_t nlistCount;     // count of nlist entries
	uint32_t stringsOffset;  // offset into this chunk of string pool
	uint32_t stringsSize;    // byte count of string pool
	uint32_t entriesOffset;  // offset into this chunk of array of dyld_cache_local_symbols_entry
	uint32_t entriesCount;   // number of elements in dyld_cache_local_symbols_entry array
};

struct PACKED_STRUCT dyld_cache_local_symbols_entry
{
	uint32_t dylibOffset;      // offset in cache file of start of dylib
	uint32_t nlistStartIndex;  // start index of locals for this dylib
	uint32_t nlistCount;       // number of local symbols for this dylib
};

struct PACKED_STRUCT dyld_cache_local_symbols_entry_64
{
	uint64_t dylibOffset;      // offset in cache buffer of start of dylib
	uint32_t nlistStartIndex;  // start index of locals for this dylib
	uint32_t nlistCount;       // number of local symbols for this dylib
};

union dyld_cache_slide_pointer3
{
	uint64_t raw;
	struct
	{
		uint64_t pointerValue : 51, offsetToNextPointer : 11, unused : 2;
	} plain;

	struct
	{
		uint64_t offsetFromSharedCacheBase : 32, diversityData : 16, hasAddressDiversity : 1, key : 2,
			offsetToNextPointer : 11, unused : 1,
			authenticated : 1;  // = 1;
	} auth;
};


struct PACKED_STRUCT dyld_cache_header
{
	char magic[16];                  // e.g. "dyld_v0    i386"
	uint32_t mappingOffset;          // file offset to first dyld_cache_mapping_info
	uint32_t mappingCount;           // number of dyld_cache_mapping_info entries
	uint32_t imagesOffsetOld;        // UNUSED: moved to imagesOffset to prevent older dsc_extarctors from crashing
	uint32_t imagesCountOld;         // UNUSED: moved to imagesCount to prevent older dsc_extarctors from crashing
	uint64_t dyldBaseAddress;        // base address of dyld when cache was built
	uint64_t codeSignatureOffset;    // file offset of code signature blob
	uint64_t codeSignatureSize;      // size of code signature blob (zero means to end of file)
	uint64_t slideInfoOffsetUnused;  // unused.  Used to be file offset of kernel slid info
	uint64_t slideInfoSizeUnused;    // unused.  Used to be size of kernel slid info
	uint64_t localSymbolsOffset;     // file offset of where local symbols are stored
	uint64_t localSymbolsSize;       // size of local symbols information
	uint8_t uuid[16];                // unique value for each shared cache file
	uint64_t cacheType;              // 0 for development, 1 for production, 2 for multi-cache
	uint32_t branchPoolsOffset;      // file offset to table of uint64_t pool addresses
	uint32_t branchPoolsCount;       // number of uint64_t entries
	uint64_t dyldInCacheMH;          // (unslid) address of mach_header of dyld in cache
	uint64_t dyldInCacheEntry;       // (unslid) address of entry point (_dyld_start) of dyld in cache
	uint64_t imagesTextOffset;       // file offset to first dyld_cache_image_text_info
	uint64_t imagesTextCount;        // number of dyld_cache_image_text_info entries
	uint64_t patchInfoAddr;          // (unslid) address of dyld_cache_patch_info
	uint64_t patchInfoSize;          // Size of all of the patch information pointed to via the dyld_cache_patch_info
	uint64_t otherImageGroupAddrUnused;  // unused
	uint64_t otherImageGroupSizeUnused;  // unused
	uint64_t progClosuresAddr;           // (unslid) address of list of program launch closures
	uint64_t progClosuresSize;           // size of list of program launch closures
	uint64_t progClosuresTrieAddr;       // (unslid) address of trie of indexes into program launch closures
	uint64_t progClosuresTrieSize;       // size of trie of indexes into program launch closures
	uint32_t platform;                   // platform number (macOS=1, etc)
	uint32_t formatVersion : 8,          // dyld3::closure::kFormatVersion
		dylibsExpectedOnDisk : 1,    // dyld should expect the dylib exists on disk and to compare inode/mtime to see if
	                                 // cache is valid
		simulator : 1,               // for simulator of specified platform
		locallyBuiltCache : 1,       // 0 for B&I built cache, 1 for locally built cache
		builtFromChainedFixups : 1,  // some dylib in cache was built using chained fixups, so patch tables must be used
	                                 // for overrides
		padding : 20;                // TBD
	uint64_t sharedRegionStart;      // base load address of cache if not slid
	uint64_t sharedRegionSize;       // overall size required to map the cache and all subCaches, if any
	uint64_t maxSlide;               // runtime slide of cache can be between zero and this value
	uint64_t dylibsImageArrayAddr;   // (unslid) address of ImageArray for dylibs in this cache
	uint64_t dylibsImageArraySize;   // size of ImageArray for dylibs in this cache
	uint64_t dylibsTrieAddr;         // (unslid) address of trie of indexes of all cached dylibs
	uint64_t dylibsTrieSize;         // size of trie of cached dylib paths
	uint64_t otherImageArrayAddr;    // (unslid) address of ImageArray for dylibs and bundles with dlopen closures
	uint64_t otherImageArraySize;    // size of ImageArray for dylibs and bundles with dlopen closures
	uint64_t otherTrieAddr;  // (unslid) address of trie of indexes of all dylibs and bundles with dlopen closures
	uint64_t otherTrieSize;  // size of trie of dylibs and bundles with dlopen closures
	uint32_t mappingWithSlideOffset;         // file offset to first dyld_cache_mapping_and_slide_info
	uint32_t mappingWithSlideCount;          // number of dyld_cache_mapping_and_slide_info entries
	uint64_t dylibsPBLStateArrayAddrUnused;  // unused
	uint64_t dylibsPBLSetAddr;               // (unslid) address of PrebuiltLoaderSet of all cached dylibs
	uint64_t programsPBLSetPoolAddr;         // (unslid) address of pool of PrebuiltLoaderSet for each program
	uint64_t programsPBLSetPoolSize;         // size of pool of PrebuiltLoaderSet for each program
	uint64_t programTrieAddr;                // (unslid) address of trie mapping program path to PrebuiltLoaderSet
	uint32_t programTrieSize;
	uint32_t osVersion;             // OS Version of dylibs in this cache for the main platform
	uint32_t altPlatform;           // e.g. iOSMac on macOS
	uint32_t altOsVersion;          // e.g. 14.0 for iOSMac
	uint64_t swiftOptsOffset;       // VM offset from cache_header* to Swift optimizations header
	uint64_t swiftOptsSize;         // size of Swift optimizations header
	uint32_t subCacheArrayOffset;   // file offset to first dyld_subcache_entry
	uint32_t subCacheArrayCount;    // number of subCache entries
	uint8_t symbolFileUUID[16];     // unique value for the shared cache file containing unmapped local symbols
	uint64_t rosettaReadOnlyAddr;   // (unslid) address of the start of where Rosetta can add read-only/executable data
	uint64_t rosettaReadOnlySize;   // maximum size of the Rosetta read-only/executable region
	uint64_t rosettaReadWriteAddr;  // (unslid) address of the start of where Rosetta can add read-write data
	uint64_t rosettaReadWriteSize;  // maximum size of the Rosetta read-write region
	uint32_t imagesOffset;          // file offset to first dyld_cache_image_info
	uint32_t imagesCount;           // number of dyld_cache_image_info entries
	uint32_t cacheSubType;          // 0 for development, 1 for production, when cacheType is multi-cache(2)
	uint32_t padding2;
	uint64_t objcOptsOffset;      // VM offset from cache_header* to ObjC optimizations header
	uint64_t objcOptsSize;        // size of ObjC optimizations header
	uint64_t cacheAtlasOffset;    // VM offset from cache_header* to embedded cache atlas for process introspection
	uint64_t cacheAtlasSize;      // size of embedded cache atlas
	uint64_t dynamicDataOffset;   // VM offset from cache_header* to the location of dyld_cache_dynamic_data_header
	uint64_t dynamicDataMaxSize;  // maximum size of space reserved from dynamic data
	uint32_t tproMappingsOffset;  // file offset to first dyld_cache_tpro_mapping_info
	uint32_t tproMappingsCount;   // number of dyld_cache_tpro_mapping_info entries
};

struct PACKED_STRUCT dyld_subcache_entry
{
	char uuid[16];
	uint64_t address;
};

struct PACKED_STRUCT dyld_subcache_entry2
{
	char uuid[16];
	uint64_t address;
	char fileExtension[32];
};