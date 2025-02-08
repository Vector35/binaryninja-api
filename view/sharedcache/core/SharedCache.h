//
// Created by kat on 5/19/23.
//

#ifndef SHAREDCACHE_SHAREDCACHE_H
#define SHAREDCACHE_SHAREDCACHE_H

#include <binaryninjaapi.h>
#include "VM.h"
#include "view/macho/machoview.h"
#include "MetadataSerializable.hpp"
#include "../api/sharedcachecore.h"

#include <optional>

DECLARE_SHAREDCACHE_API_OBJECT(BNSharedCache, SharedCache);

namespace SharedCacheCore {

	enum DSCViewState
	{
		DSCViewStateUnloaded,
		DSCViewStateLoaded,
		DSCViewStateLoadedWithImages,
	};

	const std::string SharedCacheMetadataTag = "SHAREDCACHE-SharedCacheData";

	struct MemoryRegion : public MetadataSerializable<MemoryRegion> {
		std::string prettyName;
		uint64_t start;
		uint64_t size;
		bool loaded = false;
		uint64_t rawViewOffsetIfLoaded = 0;
		bool headerInitialized = false;
		BNSegmentFlag flags;

		void Store(SerializationContext& context) const {
			MSS(prettyName);
			MSS(start);
			MSS(size);
			MSS(loaded);
			MSS(rawViewOffsetIfLoaded);
			MSS_CAST(flags, uint64_t);
		}

		static MemoryRegion Load(DeserializationContext& context) {
			return MemoryRegion {
				.MSL(prettyName),
				.MSL(start),
				.MSL(size),
				.MSL(loaded),
				.MSL(rawViewOffsetIfLoaded),
				.MSL_CAST(flags, uint64_t, BNSegmentFlag),
			};
		}
	};

	struct CacheImage : public MetadataSerializable<CacheImage> {
		std::string installName;
		uint64_t headerLocation;
		std::vector<MemoryRegion> regions;

		void Store(SerializationContext& context) const {
			MSS(installName);
			MSS(headerLocation);
			Serialize(context, "regions");
			context.writer.StartArray();
			for (auto& region : regions) {
				Serialize(context, region.AsString());
			}
			context.writer.EndArray();
		}

		static CacheImage Load(DeserializationContext& context) {
			auto regionsArray = context.doc["regions"].GetArray();
			std::vector<MemoryRegion> regions;
			for (auto& region : regionsArray) {
				regions.push_back(MemoryRegion::LoadFromString(region.GetString()));
			}

			return CacheImage {
				.MSL(installName),
				.MSL(headerLocation),
				.regions = std::move(regions),
			};
		}
	};

	#if defined(__GNUC__) || defined(__clang__)
		#define PACKED_STRUCT __attribute__((packed))
	#else
		#define PACKED_STRUCT
	#endif

	#if defined(_MSC_VER)
		#pragma pack(push, 1)
	#else

	#endif

	struct PACKED_STRUCT dyld_cache_mapping_info
	{
		uint64_t address;
		uint64_t size;
		uint64_t fileOffset;
		uint32_t maxProt;
		uint32_t initProt;
	};

	struct BackingCache : public MetadataSerializable<BackingCache> {
		std::string path;
		bool isPrimary = false;
		std::vector<dyld_cache_mapping_info> mappings;

		void Store(SerializationContext& context) const;
		static BackingCache Load(DeserializationContext& context);
	};

	struct LoadedMapping
	{
		std::shared_ptr<MMappedFileAccessor> backingFile;
		dyld_cache_mapping_info mappingInfo;
	};

	struct dyld_cache_slide_info
	{
		uint32_t    version;
		uint32_t    toc_offset;
		uint32_t    toc_count;
		uint32_t    entries_offset;
		uint32_t    entries_count;
		uint32_t    entries_size;
		// uint16_t toc[toc_count];
		// entrybitmap entries[entries_count];
	};

	struct dyld_cache_slide_info_entry {
		uint8_t  bits[4096/(8*4)]; // 128-byte bitmap
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
	#define DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA           0x8000  // index is into extras array (not starts array)
	#define DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE       0x4000  // page has no rebasing
	#define DYLD_CACHE_SLIDE_PAGE_ATTR_END             0x8000  // last chain entry for page

	#define DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE    0xFFFF    // page has no rebasing

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
		uint64_t    runtimeOffset   : 34,   // offset from the start of the shared cache
			high8           :  8,
			unused          : 10,
			next            : 11,   // 8-byte stide
			auth            :  1;   // == 0
	};

	// DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE
	struct dyld_chained_ptr_arm64e_shared_cache_auth_rebase
	{
		uint64_t    runtimeOffset   : 34,   // offset from the start of the shared cache
			diversity       : 16,
			addrDiv         :  1,
			keyIsData       :  1,   // implicitly always the 'A' key.  0 -> IA.  1 -> DA
			next            : 11,   // 8-byte stide
			auth            :  1;   // == 1
	};

	// dyld_cache_slide_info4 is used in watchOS which we are not close to supporting right now.

	#define DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE    0xFFFF    // page has no rebasing

	struct PACKED_STRUCT dyld_cache_slide_info5
	{
		uint32_t    version;            // currently 5
		uint32_t    page_size;          // currently 4096 (may also be 16384)
		uint32_t    page_starts_count;
		uint32_t    pad;                // padding to ensure the value below is on an 8-byte boundary
		uint64_t    value_add;
		// uint16_t    page_starts[/* page_starts_count */];
	};


	struct PACKED_STRUCT dyld_cache_image_info
	{
		uint64_t address;
		uint64_t modTime;
		uint64_t inode;
		uint32_t pathFileOffset;
		uint32_t pad;
	};

	union dyld_cache_slide_pointer5
	{
		uint64_t                                                raw;
		struct dyld_chained_ptr_arm64e_shared_cache_rebase      regular;
		struct dyld_chained_ptr_arm64e_shared_cache_auth_rebase auth;
	};


	struct PACKED_STRUCT dyld_cache_local_symbols_info
	{
		uint32_t	nlistOffset;		// offset into this chunk of nlist entries
		uint32_t	nlistCount;			// count of nlist entries
		uint32_t	stringsOffset;		// offset into this chunk of string pool
		uint32_t	stringsSize;		// byte count of string pool
		uint32_t	entriesOffset;		// offset into this chunk of array of dyld_cache_local_symbols_entry
		uint32_t	entriesCount;		// number of elements in dyld_cache_local_symbols_entry array
	};

	struct PACKED_STRUCT dyld_cache_local_symbols_entry
	{
		uint32_t	dylibOffset;		// offset in cache file of start of dylib
		uint32_t	nlistStartIndex;	// start index of locals for this dylib
		uint32_t	nlistCount;			// number of local symbols for this dylib
	};

	struct PACKED_STRUCT dyld_cache_local_symbols_entry_64
	{
		uint64_t    dylibOffset;        // offset in cache buffer of start of dylib
		uint32_t    nlistStartIndex;    // start index of locals for this dylib
		uint32_t    nlistCount;         // number of local symbols for this dylib
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
				authenticated : 1;	// = 1;
		} auth;
	};


	struct PACKED_STRUCT dyld_cache_header
	{
		char        magic[16];              // e.g. "dyld_v0    i386"
		uint32_t    mappingOffset;          // file offset to first dyld_cache_mapping_info
		uint32_t    mappingCount;           // number of dyld_cache_mapping_info entries
		uint32_t    imagesOffsetOld;        // UNUSED: moved to imagesOffset to prevent older dsc_extarctors from crashing
		uint32_t    imagesCountOld;         // UNUSED: moved to imagesCount to prevent older dsc_extarctors from crashing
		uint64_t    dyldBaseAddress;        // base address of dyld when cache was built
		uint64_t    codeSignatureOffset;    // file offset of code signature blob
		uint64_t    codeSignatureSize;      // size of code signature blob (zero means to end of file)
		uint64_t    slideInfoOffsetUnused;  // unused.  Used to be file offset of kernel slid info
		uint64_t    slideInfoSizeUnused;    // unused.  Used to be size of kernel slid info
		uint64_t    localSymbolsOffset;     // file offset of where local symbols are stored
		uint64_t    localSymbolsSize;       // size of local symbols information
		uint8_t     uuid[16];               // unique value for each shared cache file
		uint64_t    cacheType;              // 0 for development, 1 for production, 2 for multi-cache
		uint32_t    branchPoolsOffset;      // file offset to table of uint64_t pool addresses
		uint32_t    branchPoolsCount;       // number of uint64_t entries
		uint64_t    dyldInCacheMH;          // (unslid) address of mach_header of dyld in cache
		uint64_t    dyldInCacheEntry;       // (unslid) address of entry point (_dyld_start) of dyld in cache
		uint64_t    imagesTextOffset;       // file offset to first dyld_cache_image_text_info
		uint64_t    imagesTextCount;        // number of dyld_cache_image_text_info entries
		uint64_t    patchInfoAddr;          // (unslid) address of dyld_cache_patch_info
		uint64_t    patchInfoSize;          // Size of all of the patch information pointed to via the dyld_cache_patch_info
		uint64_t    otherImageGroupAddrUnused;    // unused
		uint64_t    otherImageGroupSizeUnused;    // unused
		uint64_t    progClosuresAddr;       // (unslid) address of list of program launch closures
		uint64_t    progClosuresSize;       // size of list of program launch closures
		uint64_t    progClosuresTrieAddr;   // (unslid) address of trie of indexes into program launch closures
		uint64_t    progClosuresTrieSize;   // size of trie of indexes into program launch closures
		uint32_t    platform;               // platform number (macOS=1, etc)
		uint32_t    formatVersion          : 8,  // dyld3::closure::kFormatVersion
					dylibsExpectedOnDisk   : 1,  // dyld should expect the dylib exists on disk and to compare inode/mtime to see if cache is valid
					simulator              : 1,  // for simulator of specified platform
					locallyBuiltCache      : 1,  // 0 for B&I built cache, 1 for locally built cache
					builtFromChainedFixups : 1,  // some dylib in cache was built using chained fixups, so patch tables must be used for overrides
					padding                : 20; // TBD
		uint64_t    sharedRegionStart;      // base load address of cache if not slid
		uint64_t    sharedRegionSize;       // overall size required to map the cache and all subCaches, if any
		uint64_t    maxSlide;               // runtime slide of cache can be between zero and this value
		uint64_t    dylibsImageArrayAddr;   // (unslid) address of ImageArray for dylibs in this cache
		uint64_t    dylibsImageArraySize;   // size of ImageArray for dylibs in this cache
		uint64_t    dylibsTrieAddr;         // (unslid) address of trie of indexes of all cached dylibs
		uint64_t    dylibsTrieSize;         // size of trie of cached dylib paths
		uint64_t    otherImageArrayAddr;    // (unslid) address of ImageArray for dylibs and bundles with dlopen closures
		uint64_t    otherImageArraySize;    // size of ImageArray for dylibs and bundles with dlopen closures
		uint64_t    otherTrieAddr;          // (unslid) address of trie of indexes of all dylibs and bundles with dlopen closures
		uint64_t    otherTrieSize;          // size of trie of dylibs and bundles with dlopen closures
		uint32_t    mappingWithSlideOffset; // file offset to first dyld_cache_mapping_and_slide_info
		uint32_t    mappingWithSlideCount;  // number of dyld_cache_mapping_and_slide_info entries
		uint64_t    dylibsPBLStateArrayAddrUnused;    // unused
		uint64_t    dylibsPBLSetAddr;           // (unslid) address of PrebuiltLoaderSet of all cached dylibs
		uint64_t    programsPBLSetPoolAddr;     // (unslid) address of pool of PrebuiltLoaderSet for each program 
		uint64_t    programsPBLSetPoolSize;     // size of pool of PrebuiltLoaderSet for each program
		uint64_t    programTrieAddr;            // (unslid) address of trie mapping program path to PrebuiltLoaderSet
		uint32_t    programTrieSize;
		uint32_t    osVersion;                  // OS Version of dylibs in this cache for the main platform
		uint32_t    altPlatform;                // e.g. iOSMac on macOS
		uint32_t    altOsVersion;               // e.g. 14.0 for iOSMac
		uint64_t    swiftOptsOffset;        // VM offset from cache_header* to Swift optimizations header
		uint64_t    swiftOptsSize;          // size of Swift optimizations header
		uint32_t    subCacheArrayOffset;    // file offset to first dyld_subcache_entry
		uint32_t    subCacheArrayCount;     // number of subCache entries
		uint8_t     symbolFileUUID[16];     // unique value for the shared cache file containing unmapped local symbols
		uint64_t    rosettaReadOnlyAddr;    // (unslid) address of the start of where Rosetta can add read-only/executable data
		uint64_t    rosettaReadOnlySize;    // maximum size of the Rosetta read-only/executable region
		uint64_t    rosettaReadWriteAddr;   // (unslid) address of the start of where Rosetta can add read-write data
		uint64_t    rosettaReadWriteSize;   // maximum size of the Rosetta read-write region
		uint32_t    imagesOffset;           // file offset to first dyld_cache_image_info
		uint32_t    imagesCount;            // number of dyld_cache_image_info entries
		uint32_t    cacheSubType;           // 0 for development, 1 for production, when cacheType is multi-cache(2)
		uint32_t    padding2;
		uint64_t    objcOptsOffset;         // VM offset from cache_header* to ObjC optimizations header
		uint64_t    objcOptsSize;           // size of ObjC optimizations header
		uint64_t    cacheAtlasOffset;       // VM offset from cache_header* to embedded cache atlas for process introspection
		uint64_t    cacheAtlasSize;         // size of embedded cache atlas
		uint64_t    dynamicDataOffset;      // VM offset from cache_header* to the location of dyld_cache_dynamic_data_header
		uint64_t    dynamicDataMaxSize;     // maximum size of space reserved from dynamic data
		uint32_t    tproMappingsOffset;     // file offset to first dyld_cache_tpro_mapping_info
		uint32_t    tproMappingsCount;      // number of dyld_cache_tpro_mapping_info entries
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

	struct ObjCOptimizationHeader
	{
		uint32_t version;
		uint32_t flags;
		uint64_t headerInfoROCacheOffset;
		uint64_t headerInfoRWCacheOffset;
		uint64_t selectorHashTableCacheOffset;
		uint64_t classHashTableCacheOffset;
		uint64_t protocolHashTableCacheOffset;
		uint64_t relativeMethodSelectorBaseAddressOffset;
	};

	#if defined(_MSC_VER)
		#pragma pack(pop)
	#else

	#endif

	using namespace BinaryNinja;
	struct SharedCacheMachOHeader : public MetadataSerializable<SharedCacheMachOHeader>
	{
		uint64_t textBase = 0;
		uint64_t loadCommandOffset = 0;
		mach_header_64 ident;
		std::string identifierPrefix;
		std::string installName;

		std::vector<std::pair<uint64_t, bool>> entryPoints;
		std::vector<uint64_t> m_entryPoints;  // list of entrypoints

		symtab_command symtab;
		dysymtab_command dysymtab;
		dyld_info_command dyldInfo;
		routines_command_64 routines64;
		function_starts_command functionStarts;
		std::vector<section_64> moduleInitSections;
		linkedit_data_command exportTrie;
		linkedit_data_command chainedFixups {};

		uint64_t relocationBase;
		// Section and program headers, internally use 64-bit form as it is a superset of 32-bit
		std::vector<segment_command_64> segments;  // only three types of sections __TEXT, __DATA, __IMPORT
		segment_command_64 linkeditSegment;
		std::vector<section_64> sections;
		std::vector<std::string> sectionNames;

		std::vector<section_64> symbolStubSections;
		std::vector<section_64> symbolPointerSections;

		std::vector<std::string> dylibs;

		build_version_command buildVersion;
		std::vector<build_tool_version> buildToolVersions;

		std::string exportTriePath;

		bool linkeditPresent = false;
		bool dysymPresent = false;
		bool dyldInfoPresent = false;
		bool exportTriePresent = false;
		bool chainedFixupsPresent = false;
		bool routinesPresent = false;
		bool functionStartsPresent = false;
		bool relocatable = false;

		void Store(SerializationContext& context) const {
			MSS(textBase);
			MSS(loadCommandOffset);
			MSS_SUBCLASS(ident);
			MSS(identifierPrefix);
			MSS(installName);
			MSS(entryPoints);
			MSS(m_entryPoints);
			MSS_SUBCLASS(symtab);
			MSS_SUBCLASS(dysymtab);
			MSS_SUBCLASS(dyldInfo);
			// MSS_SUBCLASS(routines64);
			MSS_SUBCLASS(functionStarts);
			MSS_SUBCLASS(moduleInitSections);
			MSS_SUBCLASS(exportTrie);
			MSS_SUBCLASS(chainedFixups);
			MSS(relocationBase);
			MSS_SUBCLASS(segments);
			MSS_SUBCLASS(linkeditSegment);
			MSS_SUBCLASS(sections);
			MSS(sectionNames);
			MSS_SUBCLASS(symbolStubSections);
			MSS_SUBCLASS(symbolPointerSections);
			MSS(dylibs);
			MSS_SUBCLASS(buildVersion);
			MSS_SUBCLASS(buildToolVersions);
			MSS(linkeditPresent);
			MSS(exportTriePath);
			MSS(dysymPresent);
			MSS(dyldInfoPresent);
			MSS(exportTriePresent);
			MSS(chainedFixupsPresent);
			MSS(routinesPresent);
			MSS(functionStartsPresent);
			MSS(relocatable);
		}

		static SharedCacheMachOHeader Load(DeserializationContext& context) {
			return SharedCacheMachOHeader {
				.MSL(textBase),
				.MSL(loadCommandOffset),
				.MSL(ident),
				.MSL(identifierPrefix),
				.MSL(installName),
				.MSL(entryPoints),
				.MSL(m_entryPoints),
				.MSL(symtab),
				.MSL(dysymtab),
				.MSL(dyldInfo),
				// .MSL(routines64), // FIXME CRASH but also do we even use this?
				.MSL(functionStarts),
				.MSL(moduleInitSections),
				.MSL(exportTrie),
				.MSL(chainedFixups),
				.MSL(relocationBase),
				.MSL(segments),
				.MSL(linkeditSegment),
				.MSL(sections),
				.MSL(sectionNames),
				.MSL(symbolStubSections),
				.MSL(symbolPointerSections),
				.MSL(dylibs),
				.MSL(buildVersion),
				.MSL(buildToolVersions),
				.MSL(linkeditPresent),
				.MSL(exportTriePath),
				.MSL(dysymPresent),
				.MSL(dyldInfoPresent),
				.MSL(exportTriePresent),
				.MSL(chainedFixupsPresent),
				// .MSL(routinesPresent),
				.MSL(functionStartsPresent),
				.MSL(relocatable),
			};
		}
	};

	struct MappingInfo
	{
		std::shared_ptr<MMappedFileAccessor> file;
		dyld_cache_mapping_info mappingInfo;
		uint32_t slideInfoVersion;
		dyld_cache_slide_info_v2 slideInfoV2;
		dyld_cache_slide_info_v3 slideInfoV3;
		dyld_cache_slide_info5 slideInfoV5;
	};


	class ScopedVMMapSession;

	static std::atomic<uint64_t> sharedCacheReferences = 0;

	struct SharedCacheState;

	class SharedCache : public MetadataSerializable<SharedCache, std::optional<SharedCacheState>> {
		IMPLEMENT_SHAREDCACHE_API_OBJECT(BNSharedCache);

		std::atomic<int> m_refs = 0;

	public:
		virtual void AddRef() { m_refs.fetch_add(1); }

		virtual void Release()
		{
			// undo actions will lock a file lock we hold and then wait for main thread
			// so we need to release the ref later.
			WorkerPriorityEnqueue([this]() {
				if (m_refs.fetch_sub(1) == 1)
					delete this;
			});
		}

		virtual void AddAPIRef() { AddRef(); }

		virtual void ReleaseAPIRef() { Release(); }

	public:
		enum SharedCacheFormat
		{
			RegularCacheFormat,
			SplitCacheFormat,
			LargeCacheFormat,
			iOS16CacheFormat,
		};

		void Store(SerializationContext& context) const;
		static std::optional<SharedCacheState> Load(DeserializationContext& context);

		struct ViewSpecificState;


	private:
		Ref<Logger> m_logger;
		/* VIEW STATE BEGIN -- SERIALIZE ALL OF THIS AND STORE IT IN RAW VIEW */

		// Updated as the view is loaded further, more images are added, etc
		// NOTE: Access via `State()` or `MutableState()` below.
		// `WillMutateState()` must be called before the first access to `MutableState()`.
		std::shared_ptr<SharedCacheState> m_state;
		bool m_stateIsShared = false;

		// Serialized once by PerformInitialLoad and available after m_viewState == Loaded
		bool m_metadataValid = false;

		/* VIEWSTATE END -- NOTHING PAST THIS IS SERIALIZED */
		std::shared_ptr<ViewSpecificState> m_viewSpecificState;

		/* API VIEW START */
		BinaryNinja::Ref<BinaryNinja::BinaryView> m_dscView;
		/* API VIEW END */

	private:
		void PerformInitialLoad();
		void DeserializeFromRawView();

	public:
		std::shared_ptr<VM> GetVMMap(bool mapPages = true);

		static SharedCache* GetFromDSCView(BinaryNinja::Ref<BinaryNinja::BinaryView> dscView);
		static uint64_t FastGetBackingCacheCount(BinaryNinja::Ref<BinaryNinja::BinaryView> dscView);
		bool SaveToDSCView();

		void ParseAndApplySlideInfoForFile(std::shared_ptr<MMappedFileAccessor> file);
		std::optional<uint64_t> GetImageStart(std::string installName);
		std::optional<SharedCacheMachOHeader> HeaderForAddress(uint64_t);
		bool LoadImageWithInstallName(std::string installName, bool skipObjC);
		bool LoadSectionAtAddress(uint64_t address);
		bool LoadImageContainingAddress(uint64_t address, bool skipObjC);
		void ProcessObjCSectionsForImageWithInstallName(std::string installName);
		void ProcessAllObjCSections();
		std::string NameForAddress(uint64_t address);
		std::string ImageNameForAddress(uint64_t address);
		std::vector<std::string> GetAvailableImages();

		std::vector<MemoryRegion> GetMappedRegions() const;
		bool IsMemoryMapped(uint64_t address);

		std::vector<std::pair<std::string, Ref<Symbol>>> LoadAllSymbolsAndWait();

		const std::unordered_map<std::string, uint64_t>& AllImageStarts() const;
		const std::unordered_map<uint64_t, SharedCacheMachOHeader>& AllImageHeaders() const;

		std::string SerializedImageHeaderForAddress(uint64_t address);
		std::string SerializedImageHeaderForName(std::string name);

		void FindSymbolAtAddrAndApplyToAddr(uint64_t symbolLocation, uint64_t targetLocation, bool triggerReanalysis);

		const std::vector<BackingCache>& BackingCaches() const;

		DSCViewState ViewState() const;

		explicit SharedCache(BinaryNinja::Ref<BinaryNinja::BinaryView> rawView);
		virtual ~SharedCache();

		size_t GetObjCRelativeMethodBaseAddress(const VMReader& reader) const;

private:
		std::optional<SharedCacheMachOHeader> LoadHeaderForAddress(
			std::shared_ptr<VM> vm, uint64_t address, std::string installName);
		void InitializeHeader(
			Ref<BinaryView> view, VM* vm, const SharedCacheMachOHeader& header, std::vector<MemoryRegion*> regionsToLoad);
		void ReadExportNode(std::vector<Ref<Symbol>>& symbolList, const SharedCacheMachOHeader& header, const uint8_t* begin,
			const uint8_t *end, const uint8_t* current, uint64_t textBase, const std::string& currentText);
		std::vector<Ref<Symbol>> ParseExportTrie(
			std::shared_ptr<MMappedFileAccessor> linkeditFile, const SharedCacheMachOHeader& header);
		std::shared_ptr<std::unordered_map<uint64_t, Ref<Symbol>>> GetExportListForHeader(SharedCacheMachOHeader header,
			std::function<std::shared_ptr<MMappedFileAccessor>()> provideLinkeditFile, bool* didModifyExportList = nullptr);


		Ref<TypeLibrary> TypeLibraryForImage(const std::string& installName);

		size_t GetBaseAddress() const;
		std::optional<ObjCOptimizationHeader> GetObjCOptimizationHeader(VMReader reader) const;

		const SharedCacheState& State() const { return *m_state; }
		struct SharedCacheState& MutableState() { AssertMutable(); return *m_state; }

		void AssertMutable() const;

		// Ensures that the state is uniquely owned, copying it if it is not.
		// Must be called before first access to `MutableState()` after the state
		// is loaded from the cache. Can safely be called multiple times.
		void WillMutateState();
	};

}

void InitDSCViewType();

#endif //SHAREDCACHE_SHAREDCACHE_H

