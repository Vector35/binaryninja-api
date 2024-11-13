//
// Created by kat on 5/19/23.
//

#include <binaryninjaapi.h>
#include "DSCView.h"
#include "VM.h"
#include "view/macho/machoview.h"
#include "MetadataSerializable.hpp"
#include "../api/sharedcachecore.h"

#ifndef SHAREDCACHE_SHAREDCACHE_H
#define SHAREDCACHE_SHAREDCACHE_H

DECLARE_SHAREDCACHE_API_OBJECT(BNSharedCache, SharedCache);

namespace SharedCacheCore {

	enum DSCViewState
	{
		DSCViewStateUnloaded,
		DSCViewStateLoaded,
		DSCViewStateLoadedWithImages,
	};


	const std::string SharedCacheMetadataTag = "SHAREDCACHE-SharedCacheData";

	struct MemoryRegion : public MetadataSerializable
	{
		std::string prettyName;
		uint64_t start;
		uint64_t size;
		bool loaded = false;
		uint64_t rawViewOffsetIfLoaded = 0;
		bool headerInitialized = false;
		BNSegmentFlag flags;

		void Store() override
		{
			MSS(prettyName);
			MSS(start);
			MSS(size);
			MSS(loaded);
			MSS(rawViewOffsetIfLoaded);
			MSS_CAST(flags, uint64_t);
		}

		void Load() override
		{
			MSL(prettyName);
			MSL(start);
			MSL(size);
			MSL(loaded);
			MSL(rawViewOffsetIfLoaded);
			MSL_CAST(flags, uint64_t, BNSegmentFlag);
		}
	};

	struct CacheImage : public MetadataSerializable
	{
		std::string installName;
		uint64_t headerLocation;
		std::vector<MemoryRegion> regions;

		void Store() override
		{
			MSS(installName);
			MSS(headerLocation);
			rapidjson::Value key("regions", m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			for (auto& region : regions)
			{
				bArr.PushBack(rapidjson::Value(region.AsString().c_str(), m_activeContext.allocator), m_activeContext.allocator);
			}
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Load() override
		{
			MSL(installName);
			MSL(headerLocation);
			auto bArr = m_activeDeserContext.doc["regions"].GetArray();
			regions.clear();
			for (auto& region : bArr)
			{
				MemoryRegion r;
				r.LoadFromString(region.GetString());
				regions.push_back(r);
			}
		}
	};

	struct BackingCache : public MetadataSerializable
	{
		std::string path;
		bool isPrimary = false;
		std::vector<std::pair<uint64_t, std::pair<uint64_t, uint64_t>>> mappings;

		void Store() override
		{
			MSS(path);
			MSS(isPrimary);
			MSS(mappings);
		}
		void Load() override
		{
			MSL(path);
			MSL(isPrimary);
			MSL(mappings);
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

	struct LoadedMapping
	{
		std::shared_ptr<MMappedFileAccessor> backingFile;
		dyld_cache_mapping_info mappingInfo;
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
		char magic[16];					 // e.g. "dyld_v0    i386"
		uint32_t mappingOffset;			 // file offset to first dyld_cache_mapping_info
		uint32_t mappingCount;			 // number of dyld_cache_mapping_info entries
		uint32_t imagesOffsetOld;		 // UNUSED: moved to imagesOffset to prevent older dsc_extarctors from crashing
		uint32_t imagesCountOld;		 // UNUSED: moved to imagesCount to prevent older dsc_extarctors from crashing
		uint64_t dyldBaseAddress;		 // base address of dyld when cache was built
		uint64_t codeSignatureOffset;	 // file offset of code signature blob
		uint64_t codeSignatureSize;		 // size of code signature blob (zero means to end of file)
		uint64_t slideInfoOffsetUnused;	 // unused.  Used to be file offset of kernel slid info
		uint64_t slideInfoSizeUnused;	 // unused.  Used to be size of kernel slid info
		uint64_t localSymbolsOffset;	 // file offset of where local symbols are stored
		uint64_t localSymbolsSize;		 // size of local symbols information
		uint8_t uuid[16];				 // unique value for each shared cache file
		uint64_t cacheType;				 // 0 for development, 1 for production // Kat: , 2 for iOS 16?
		uint32_t branchPoolsOffset;		 // file offset to table of uint64_t pool addresses
		uint32_t branchPoolsCount;		 // number of uint64_t entries
		uint64_t accelerateInfoAddr;	 // (unslid) address of optimization info
		uint64_t accelerateInfoSize;	 // size of optimization info
		uint64_t imagesTextOffset;		 // file offset to first dyld_cache_image_text_info
		uint64_t imagesTextCount;		 // number of dyld_cache_image_text_info entries
		uint64_t patchInfoAddr;			 // (unslid) address of dyld_cache_patch_info
		uint64_t patchInfoSize;	 // Size of all of the patch information pointed to via the dyld_cache_patch_info
		uint64_t otherImageGroupAddrUnused;	 // unused
		uint64_t otherImageGroupSizeUnused;	 // unused
		uint64_t progClosuresAddr;			 // (unslid) address of list of program launch closures
		uint64_t progClosuresSize;			 // size of list of program launch closures
		uint64_t progClosuresTrieAddr;		 // (unslid) address of trie of indexes into program launch closures
		uint64_t progClosuresTrieSize;		 // size of trie of indexes into program launch closures
		uint32_t platform;					 // platform number (macOS=1, etc)
		uint32_t formatVersion : 8,			 // dyld3::closure::kFormatVersion
			dylibsExpectedOnDisk : 1,  // dyld should expect the dylib exists on disk and to compare inode/mtime to see if cache is valid
			simulator : 1,			   // for simulator of specified platform
			locallyBuiltCache : 1,	   // 0 for B&I built cache, 1 for locally built cache
			builtFromChainedFixups : 1,	 // some dylib in cache was built using chained fixups, so patch tables must be used for overrides
			padding : 20;				 // TBD
		uint64_t sharedRegionStart;		 // base load address of cache if not slid
		uint64_t sharedRegionSize;		 // overall size required to map the cache and all subCaches, if any
		uint64_t maxSlide;				 // runtime slide of cache can be between zero and this value
		uint64_t dylibsImageArrayAddr;	 // (unslid) address of ImageArray for dylibs in this cache
		uint64_t dylibsImageArraySize;	 // size of ImageArray for dylibs in this cache
		uint64_t dylibsTrieAddr;		 // (unslid) address of trie of indexes of all cached dylibs
		uint64_t dylibsTrieSize;		 // size of trie of cached dylib paths
		uint64_t otherImageArrayAddr;	 // (unslid) address of ImageArray for dylibs and bundles with dlopen closures
		uint64_t otherImageArraySize;	 // size of ImageArray for dylibs and bundles with dlopen closures
		uint64_t otherTrieAddr;	 // (unslid) address of trie of indexes of all dylibs and bundles with dlopen closures
		uint64_t otherTrieSize;	 // size of trie of dylibs and bundles with dlopen closures
		uint32_t mappingWithSlideOffset;		 // file offset to first dyld_cache_mapping_and_slide_info
		uint32_t mappingWithSlideCount;			 // number of dyld_cache_mapping_and_slide_info entries
		uint64_t dylibsPBLStateArrayAddrUnused;	 // unused
		uint64_t dylibsPBLSetAddr;				 // (unslid) address of PrebuiltLoaderSet of all cached dylibs
		uint64_t programsPBLSetPoolAddr;		 // (unslid) address of pool of PrebuiltLoaderSet for each program
		uint64_t programsPBLSetPoolSize;		 // size of pool of PrebuiltLoaderSet for each program
		uint64_t programTrieAddr;				 // (unslid) address of trie mapping program path to PrebuiltLoaderSet
		uint32_t programTrieSize;
		uint32_t osVersion;				// OS Version of dylibs in this cache for the main platform
		uint32_t altPlatform;			// e.g. iOSMac on macOS
		uint32_t altOsVersion;			// e.g. 14.0 for iOSMac
		uint64_t swiftOptsOffset;		// file offset to Swift optimizations header
		uint64_t swiftOptsSize;			// size of Swift optimizations header
		uint32_t subCacheArrayOffset;	// file offset to first dyld_subcache_entry
		uint32_t subCacheArrayCount;	// number of subCache entries
		uint8_t symbolFileUUID[16];		// unique value for the shared cache file containing unmapped local symbols
		uint64_t rosettaReadOnlyAddr;	// (unslid) address of the start of where Rosetta can add read-only/executable data
		uint64_t rosettaReadOnlySize;	// maximum size of the Rosetta read-only/executable region
		uint64_t rosettaReadWriteAddr;	// (unslid) address of the start of where Rosetta can add read-write data
		uint64_t rosettaReadWriteSize;	// maximum size of the Rosetta read-write region
		uint32_t imagesOffset;			// file offset to first dyld_cache_image_info
		uint32_t imagesCount;			// number of dyld_cache_image_info entries
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

	#if defined(_MSC_VER)
		#pragma pack(pop)
	#else

	#endif

	using namespace BinaryNinja;
	struct SharedCacheMachOHeader : public MetadataSerializable
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
		void Serialize(const std::string& name, mach_header_64 b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			bArr.PushBack(b.magic, m_activeContext.allocator);
			bArr.PushBack(b.cputype, m_activeContext.allocator);
			bArr.PushBack(b.cpusubtype, m_activeContext.allocator);
			bArr.PushBack(b.filetype, m_activeContext.allocator);
			bArr.PushBack(b.ncmds, m_activeContext.allocator);
			bArr.PushBack(b.sizeofcmds, m_activeContext.allocator);
			bArr.PushBack(b.flags, m_activeContext.allocator);
			bArr.PushBack(b.reserved, m_activeContext.allocator);
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, mach_header_64& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			b.magic = bArr[0].GetUint();
			b.cputype = bArr[1].GetUint();
			b.cpusubtype = bArr[2].GetUint();
			b.filetype = bArr[3].GetUint();
			b.ncmds = bArr[4].GetUint();
			b.sizeofcmds = bArr[5].GetUint();
			b.flags = bArr[6].GetUint();
			b.reserved = bArr[7].GetUint();
		}

		void Serialize(const std::string& name, symtab_command b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			bArr.PushBack(b.cmd, m_activeContext.allocator);
			bArr.PushBack(b.cmdsize, m_activeContext.allocator);
			bArr.PushBack(b.symoff, m_activeContext.allocator);
			bArr.PushBack(b.nsyms, m_activeContext.allocator);
			bArr.PushBack(b.stroff, m_activeContext.allocator);
			bArr.PushBack(b.strsize, m_activeContext.allocator);
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, symtab_command& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			b.cmd = bArr[0].GetUint();
			b.cmdsize = bArr[1].GetUint();
			b.symoff = bArr[2].GetUint();
			b.nsyms = bArr[3].GetUint();
			b.stroff = bArr[4].GetUint();
			b.strsize = bArr[5].GetUint();
		}

		void Serialize(const std::string& name, dysymtab_command b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			bArr.PushBack(b.cmd, m_activeContext.allocator);
			bArr.PushBack(b.cmdsize, m_activeContext.allocator);
			bArr.PushBack(b.ilocalsym, m_activeContext.allocator);
			bArr.PushBack(b.nlocalsym, m_activeContext.allocator);
			bArr.PushBack(b.iextdefsym, m_activeContext.allocator);
			bArr.PushBack(b.nextdefsym, m_activeContext.allocator);
			bArr.PushBack(b.iundefsym, m_activeContext.allocator);
			bArr.PushBack(b.nundefsym, m_activeContext.allocator);
			bArr.PushBack(b.tocoff, m_activeContext.allocator);
			bArr.PushBack(b.ntoc, m_activeContext.allocator);
			bArr.PushBack(b.modtaboff, m_activeContext.allocator);
			bArr.PushBack(b.nmodtab, m_activeContext.allocator);
			bArr.PushBack(b.extrefsymoff, m_activeContext.allocator);
			bArr.PushBack(b.nextrefsyms, m_activeContext.allocator);
			bArr.PushBack(b.indirectsymoff, m_activeContext.allocator);
			bArr.PushBack(b.nindirectsyms, m_activeContext.allocator);
			bArr.PushBack(b.extreloff, m_activeContext.allocator);
			bArr.PushBack(b.nextrel, m_activeContext.allocator);
			bArr.PushBack(b.locreloff, m_activeContext.allocator);
			bArr.PushBack(b.nlocrel, m_activeContext.allocator);
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, dysymtab_command& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			b.cmd = bArr[0].GetUint();
			b.cmdsize = bArr[1].GetUint();
			b.ilocalsym = bArr[2].GetUint();
			b.nlocalsym = bArr[3].GetUint();
			b.iextdefsym = bArr[4].GetUint();
			b.nextdefsym = bArr[5].GetUint();
			b.iundefsym = bArr[6].GetUint();
			b.nundefsym = bArr[7].GetUint();
			b.tocoff = bArr[8].GetUint();
			b.ntoc = bArr[9].GetUint();
			b.modtaboff = bArr[10].GetUint();
			b.nmodtab = bArr[11].GetUint();
			b.extrefsymoff = bArr[12].GetUint();
			b.nextrefsyms = bArr[13].GetUint();
			b.indirectsymoff = bArr[14].GetUint();
			b.nindirectsyms = bArr[15].GetUint();
			b.extreloff = bArr[16].GetUint();
			b.nextrel = bArr[17].GetUint();
			b.locreloff = bArr[18].GetUint();
			b.nlocrel = bArr[19].GetUint();
		}

		void Serialize(const std::string& name, dyld_info_command b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			bArr.PushBack(b.cmd, m_activeContext.allocator);
			bArr.PushBack(b.cmdsize, m_activeContext.allocator);
			bArr.PushBack(b.rebase_off, m_activeContext.allocator);
			bArr.PushBack(b.rebase_size, m_activeContext.allocator);
			bArr.PushBack(b.bind_off, m_activeContext.allocator);
			bArr.PushBack(b.bind_size, m_activeContext.allocator);
			bArr.PushBack(b.weak_bind_off, m_activeContext.allocator);
			bArr.PushBack(b.weak_bind_size, m_activeContext.allocator);
			bArr.PushBack(b.lazy_bind_off, m_activeContext.allocator);
			bArr.PushBack(b.lazy_bind_size, m_activeContext.allocator);
			bArr.PushBack(b.export_off, m_activeContext.allocator);
			bArr.PushBack(b.export_size, m_activeContext.allocator);
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, dyld_info_command& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			b.cmd = bArr[0].GetUint();
			b.cmdsize = bArr[1].GetUint();
			b.rebase_off = bArr[2].GetUint();
			b.rebase_size = bArr[3].GetUint();
			b.bind_off = bArr[4].GetUint();
			b.bind_size = bArr[5].GetUint();
			b.weak_bind_off = bArr[6].GetUint();
			b.weak_bind_size = bArr[7].GetUint();
			b.lazy_bind_off = bArr[8].GetUint();
			b.lazy_bind_size = bArr[9].GetUint();
			b.export_off = bArr[10].GetUint();
			b.export_size = bArr[11].GetUint();
		}

		void Serialize(const std::string& name, routines_command_64 b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			bArr.PushBack(b.cmd, m_activeContext.allocator);
			bArr.PushBack(b.cmdsize, m_activeContext.allocator);
			bArr.PushBack(b.init_address, m_activeContext.allocator);
			bArr.PushBack(b.init_module, m_activeContext.allocator);
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, routines_command_64& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			b.cmd = bArr[0].GetUint();
			b.cmdsize = bArr[1].GetUint();
			b.init_address = bArr[2].GetUint();
			b.init_module = bArr[3].GetUint();
		}

		void Serialize(const std::string& name, function_starts_command b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			bArr.PushBack(b.cmd, m_activeContext.allocator);
			bArr.PushBack(b.cmdsize, m_activeContext.allocator);
			bArr.PushBack(b.funcoff, m_activeContext.allocator);
			bArr.PushBack(b.funcsize, m_activeContext.allocator);
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, function_starts_command& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			b.cmd = bArr[0].GetUint();
			b.cmdsize = bArr[1].GetUint();
			b.funcoff = bArr[2].GetUint();
			b.funcsize = bArr[3].GetUint();
		}

		void Serialize(const std::string& name, std::vector<section_64> b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			for (auto& s : b)
			{
				rapidjson::Value sArr(rapidjson::kArrayType);
				std::string sectNameStr;
				char sectName[16];
				memcpy(sectName, s.sectname, 16);
				sectName[15] = 0;
				sectNameStr = std::string(sectName);
				sArr.PushBack(
					rapidjson::Value(sectNameStr.c_str(), m_activeContext.allocator), m_activeContext.allocator);
				std::string segNameStr;
				char segName[16];
				memcpy(segName, s.segname, 16);
				segName[15] = 0;
				segNameStr = std::string(segName);
				sArr.PushBack(
					rapidjson::Value(segNameStr.c_str(), m_activeContext.allocator), m_activeContext.allocator);
				sArr.PushBack(s.addr, m_activeContext.allocator);
				sArr.PushBack(s.size, m_activeContext.allocator);
				sArr.PushBack(s.offset, m_activeContext.allocator);
				sArr.PushBack(s.align, m_activeContext.allocator);
				sArr.PushBack(s.reloff, m_activeContext.allocator);
				sArr.PushBack(s.nreloc, m_activeContext.allocator);
				sArr.PushBack(s.flags, m_activeContext.allocator);
				sArr.PushBack(s.reserved1, m_activeContext.allocator);
				sArr.PushBack(s.reserved2, m_activeContext.allocator);
				sArr.PushBack(s.reserved3, m_activeContext.allocator);
				bArr.PushBack(sArr, m_activeContext.allocator);
			}
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, std::vector<section_64>& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			for (auto& s : bArr)
			{
				section_64 sec;
				auto s2 = s.GetArray();
				std::string sectNameStr = s2[0].GetString();
				memset(sec.sectname, 0, 16);
				memcpy(sec.sectname, sectNameStr.c_str(), sectNameStr.size());
				std::string segNameStr = s2[1].GetString();
				memset(sec.segname, 0, 16);
				memcpy(sec.segname, segNameStr.c_str(), segNameStr.size());
				sec.addr = s2[2].GetUint64();
				sec.size = s2[3].GetUint64();
				sec.offset = s2[4].GetUint();
				sec.align = s2[5].GetUint();
				sec.reloff = s2[6].GetUint();
				sec.nreloc = s2[7].GetUint();
				sec.flags = s2[8].GetUint();
				sec.reserved1 = s2[9].GetUint();
				sec.reserved2 = s2[10].GetUint();
				sec.reserved3 = s2[11].GetUint();
				b.push_back(sec);
			}
		}

		void Serialize(const std::string& name, linkedit_data_command b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			bArr.PushBack(b.cmd, m_activeContext.allocator);
			bArr.PushBack(b.cmdsize, m_activeContext.allocator);
			bArr.PushBack(b.dataoff, m_activeContext.allocator);
			bArr.PushBack(b.datasize, m_activeContext.allocator);
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, linkedit_data_command& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			b.cmd = bArr[0].GetUint();
			b.cmdsize = bArr[1].GetUint();
			b.dataoff = bArr[2].GetUint();
			b.datasize = bArr[3].GetUint();
		}

		void Serialize(const std::string& name, segment_command_64 b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			std::string segNameStr;
			char segName[16];
			memcpy(segName, b.segname, 16);
			segName[15] = 0;
			segNameStr = std::string(segName);
			bArr.PushBack(rapidjson::Value(segNameStr.c_str(), m_activeContext.allocator), m_activeContext.allocator);
			bArr.PushBack(b.vmaddr, m_activeContext.allocator);
			bArr.PushBack(b.vmsize, m_activeContext.allocator);
			bArr.PushBack(b.fileoff, m_activeContext.allocator);
			bArr.PushBack(b.filesize, m_activeContext.allocator);
			bArr.PushBack(b.maxprot, m_activeContext.allocator);
			bArr.PushBack(b.initprot, m_activeContext.allocator);
			bArr.PushBack(b.nsects, m_activeContext.allocator);
			bArr.PushBack(b.flags, m_activeContext.allocator);
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, segment_command_64& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			std::string segNameStr = bArr[0].GetString();
			memset(b.segname, 0, 16);
			memcpy(b.segname, segNameStr.c_str(), segNameStr.size());
			b.vmaddr = bArr[1].GetUint64();
			b.vmsize = bArr[2].GetUint64();
			b.fileoff = bArr[3].GetUint64();
			b.filesize = bArr[4].GetUint64();
			b.maxprot = bArr[5].GetUint();
			b.initprot = bArr[6].GetUint();
			b.nsects = bArr[7].GetUint();
			b.flags = bArr[8].GetUint();
		}

		void Serialize(const std::string& name, std::vector<segment_command_64> b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			for (auto& s : b)
			{
				rapidjson::Value sArr(rapidjson::kArrayType);
				std::string segNameStr;
				char segName[16];
				memcpy(segName, s.segname, 16);
				segName[15] = 0;
				segNameStr = std::string(segName);
				sArr.PushBack(
					rapidjson::Value(segNameStr.c_str(), m_activeContext.allocator), m_activeContext.allocator);
				sArr.PushBack(s.vmaddr, m_activeContext.allocator);
				sArr.PushBack(s.vmsize, m_activeContext.allocator);
				sArr.PushBack(s.fileoff, m_activeContext.allocator);
				sArr.PushBack(s.filesize, m_activeContext.allocator);
				sArr.PushBack(s.maxprot, m_activeContext.allocator);
				sArr.PushBack(s.initprot, m_activeContext.allocator);
				sArr.PushBack(s.nsects, m_activeContext.allocator);
				sArr.PushBack(s.flags, m_activeContext.allocator);
				bArr.PushBack(sArr, m_activeContext.allocator);
			}
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, std::vector<segment_command_64>& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			for (auto& s : bArr)
			{
				segment_command_64 sec;
				auto s2 = s.GetArray();
				std::string segNameStr = s2[0].GetString();
				memset(sec.segname, 0, 16);
				memcpy(sec.segname, segNameStr.c_str(), segNameStr.size());
				sec.vmaddr = s2[1].GetUint64();
				sec.vmsize = s2[2].GetUint64();
				sec.fileoff = s2[3].GetUint64();
				sec.filesize = s2[4].GetUint64();
				sec.maxprot = s2[5].GetUint();
				sec.initprot = s2[6].GetUint();
				sec.nsects = s2[7].GetUint();
				sec.flags = s2[8].GetUint();
				b.push_back(sec);
			}
		}

		void Serialize(const std::string& name, build_version_command b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			bArr.PushBack(b.cmd, m_activeContext.allocator);
			bArr.PushBack(b.cmdsize, m_activeContext.allocator);
			bArr.PushBack(b.platform, m_activeContext.allocator);
			bArr.PushBack(b.minos, m_activeContext.allocator);
			bArr.PushBack(b.sdk, m_activeContext.allocator);
			bArr.PushBack(b.ntools, m_activeContext.allocator);
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, build_version_command& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			b.cmd = bArr[0].GetUint();
			b.cmdsize = bArr[1].GetUint();
			b.platform = bArr[2].GetUint();
			b.minos = bArr[3].GetUint();
			b.sdk = bArr[4].GetUint();
			b.ntools = bArr[5].GetUint();
		}

		void Serialize(const std::string& name, std::vector<build_tool_version> b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			for (auto& s : b)
			{
				rapidjson::Value sArr(rapidjson::kArrayType);
				sArr.PushBack(s.tool, m_activeContext.allocator);
				sArr.PushBack(s.version, m_activeContext.allocator);
				bArr.PushBack(sArr, m_activeContext.allocator);
			}
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, std::vector<build_tool_version>& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			for (auto& s : bArr)
			{
				build_tool_version sec;
				auto s2 = s.GetArray();
				sec.tool = s2[0].GetUint();
				sec.version = s2[1].GetUint();
				b.push_back(sec);
			}
		}

		void Store() override
		{
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
		void Load() override
		{
			MSL(textBase);
			MSL(loadCommandOffset);
			MSL_SUBCLASS(ident);
			MSL(identifierPrefix);
			MSL(installName);
			MSL(entryPoints);
			MSL(m_entryPoints);
			MSL_SUBCLASS(symtab);
			MSL_SUBCLASS(dysymtab);
			MSL_SUBCLASS(dyldInfo);
			// MSL_SUBCLASS(routines64); // FIXME CRASH but also do we even use this?
			MSL_SUBCLASS(functionStarts);
			MSL_SUBCLASS(moduleInitSections);
			MSL_SUBCLASS(exportTrie);
			MSL_SUBCLASS(chainedFixups);
			MSL(relocationBase);
			MSL_SUBCLASS(segments);
			MSL_SUBCLASS(linkeditSegment);
			MSL_SUBCLASS(sections);
			MSL(sectionNames);
			MSL_SUBCLASS(symbolStubSections);
			MSL_SUBCLASS(symbolPointerSections);
			MSL(dylibs);
			MSL_SUBCLASS(buildVersion);
			MSL_SUBCLASS(buildToolVersions);
			MSL(linkeditPresent);
			MSL(exportTriePath);
			MSL(dysymPresent);
			MSL(dyldInfoPresent);
			MSL(exportTriePresent);
			MSL(chainedFixupsPresent);
			// MSL(routinesPresent);
			MSL(functionStartsPresent);
			MSL(relocatable);
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

	class SharedCache : public MetadataSerializable
	{
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

		void Store() override
		{
			m_activeContext.doc.AddMember("metadataVersion", METADATA_VERSION, m_activeContext.allocator);

			MSS(m_viewState);
			MSS_CAST(m_cacheFormat, uint8_t);
			MSS(m_imageStarts);
			MSS(m_baseFilePath);
			rapidjson::Value headers(rapidjson::kArrayType);
			for (auto [k, v] : m_headers)
			{
				headers.PushBack(v.AsDocument(), m_activeContext.allocator);
			}
			m_activeContext.doc.AddMember("headers", headers, m_activeContext.allocator);
			// std::vector<std::pair<uint64_t, std::vector<std::pair<uint64_t, std::pair<BNSymbolType, std::string>>>>> m_exportInfos
			rapidjson::Value exportInfos(rapidjson::kArrayType);
			for (auto& exportInfo : m_exportInfos)
			{
				rapidjson::Value exportInfoArr(rapidjson::kArrayType);
				for (auto& exportInfoPair : exportInfo.second)
				{
					rapidjson::Value exportInfoPairArr(rapidjson::kArrayType);
					exportInfoPairArr.PushBack(exportInfoPair.first, m_activeContext.allocator);
					exportInfoPairArr.PushBack(exportInfoPair.second.first, m_activeContext.allocator);
					exportInfoPairArr.PushBack(
						rapidjson::Value(exportInfoPair.second.second.c_str(), m_activeContext.allocator),
						m_activeContext.allocator);
					exportInfoArr.PushBack(exportInfoPairArr, m_activeContext.allocator);
				}
				exportInfos.PushBack(exportInfoArr, m_activeContext.allocator);
			}
			m_activeContext.doc.AddMember("exportInfos", exportInfos, m_activeContext.allocator);
			// std::vector<std::pair<uint64_t, std::vector<std::pair<uint64_t, std::pair<BNSymbolType, std::string>>>>> m_symbolInfos
			rapidjson::Value symbolInfos(rapidjson::kArrayType);
			for (auto& symbolInfo : m_symbolInfos)
			{
				rapidjson::Value symbolInfoArr(rapidjson::kArrayType);
				for (auto& symbolInfoPair : symbolInfo.second)
				{
					rapidjson::Value symbolInfoPairArr(rapidjson::kArrayType);
					symbolInfoPairArr.PushBack(symbolInfoPair.first, m_activeContext.allocator);
					symbolInfoPairArr.PushBack(symbolInfoPair.second.first, m_activeContext.allocator);
					symbolInfoPairArr.PushBack(
						rapidjson::Value(symbolInfoPair.second.second.c_str(), m_activeContext.allocator),
						m_activeContext.allocator);
					symbolInfoArr.PushBack(symbolInfoPairArr, m_activeContext.allocator);
				}
				symbolInfos.PushBack(symbolInfoArr, m_activeContext.allocator);
			}
			m_activeContext.doc.AddMember("symbolInfos", symbolInfos, m_activeContext.allocator);

			rapidjson::Value backingCaches(rapidjson::kArrayType);
			for (auto bc : m_backingCaches)
			{
				backingCaches.PushBack(bc.AsDocument(), m_activeContext.allocator);
			}
			m_activeContext.doc.AddMember("backingCaches", backingCaches, m_activeContext.allocator);
			rapidjson::Value stubIslands(rapidjson::kArrayType);
			for (auto si : m_stubIslandRegions)
			{
				stubIslands.PushBack(si.AsDocument(), m_activeContext.allocator);
			}
			rapidjson::Value images(rapidjson::kArrayType);
			for (auto img : m_images)
			{
				images.PushBack(img.AsDocument(), m_activeContext.allocator);
			}
			m_activeContext.doc.AddMember("images", images, m_activeContext.allocator);
			rapidjson::Value regionsMappedIntoMemory(rapidjson::kArrayType);
			for (auto r : m_regionsMappedIntoMemory)
			{
				regionsMappedIntoMemory.PushBack(r.AsDocument(), m_activeContext.allocator);
			}
			m_activeContext.doc.AddMember("regionsMappedIntoMemory", regionsMappedIntoMemory, m_activeContext.allocator);
			m_activeContext.doc.AddMember("stubIslands", stubIslands, m_activeContext.allocator);
			rapidjson::Value dyldDataSections(rapidjson::kArrayType);
			for (auto si : m_dyldDataRegions)
			{
				dyldDataSections.PushBack(si.AsDocument(), m_activeContext.allocator);
			}
			m_activeContext.doc.AddMember("dyldDataSections", dyldDataSections, m_activeContext.allocator);
			rapidjson::Value nonImageRegions(rapidjson::kArrayType);
			for (auto si : m_nonImageRegions)
			{
				nonImageRegions.PushBack(si.AsDocument(), m_activeContext.allocator);
			}
			m_activeContext.doc.AddMember("nonImageRegions", nonImageRegions, m_activeContext.allocator);
		}
		void Load() override
		{
			if (m_activeDeserContext.doc.HasMember("metadataVersion"))
			{
				if (m_activeDeserContext.doc["metadataVersion"].GetUint() != METADATA_VERSION)
				{
					m_logger->LogError("Shared Cache metadata version mismatch");
					return;
				}
			}
			else
			{
				m_logger->LogError("Shared Cache metadata version missing");
				return;
			}
			m_viewState = MSL_CAST(m_viewState, uint8_t, DSCViewState);
			m_cacheFormat = MSL_CAST(m_cacheFormat, uint8_t, SharedCacheFormat);
			m_headers.clear();
			for (auto& startAndHeader : m_activeDeserContext.doc["headers"].GetArray())
			{
				SharedCacheMachOHeader header;
				header.LoadFromValue(startAndHeader);
				m_headers[header.textBase] = header;
			}
			MSL(m_imageStarts);
			MSL(m_baseFilePath);
			m_exportInfos.clear();
			for (auto& exportInfo : m_activeDeserContext.doc["exportInfos"].GetArray())
			{
				std::vector<std::pair<uint64_t, std::pair<BNSymbolType, std::string>>> exportInfoVec;
				for (auto& exportInfoPair : exportInfo.GetArray())
				{
					exportInfoVec.push_back({exportInfoPair[0].GetUint64(),
						{(BNSymbolType)exportInfoPair[1].GetUint(), exportInfoPair[2].GetString()}});
				}
				m_exportInfos[exportInfo[0].GetUint64()] = exportInfoVec;
			}
			m_symbolInfos.clear();
			for (auto& symbolInfo : m_activeDeserContext.doc["symbolInfos"].GetArray())
			{
				std::vector<std::pair<uint64_t, std::pair<BNSymbolType, std::string>>> symbolInfoVec;
				for (auto& symbolInfoPair : symbolInfo.GetArray())
				{
					symbolInfoVec.push_back({symbolInfoPair[0].GetUint64(),
						{(BNSymbolType)symbolInfoPair[1].GetUint(), symbolInfoPair[2].GetString()}});
				}
				m_symbolInfos[symbolInfo[0].GetUint64()] = symbolInfoVec;
			}
			m_backingCaches.clear();
			for (auto& bcV : m_activeDeserContext.doc["backingCaches"].GetArray())
			{
				BackingCache bc;
				bc.LoadFromValue(bcV);
				m_backingCaches.push_back(bc);
			}
			m_images.clear();
			for (auto& imgV : m_activeDeserContext.doc["images"].GetArray())
			{
				CacheImage img;
				img.LoadFromValue(imgV);
				m_images.push_back(img);
			}
			m_regionsMappedIntoMemory.clear();
			for (auto& rV : m_activeDeserContext.doc["regionsMappedIntoMemory"].GetArray())
			{
				MemoryRegion r;
				r.LoadFromValue(rV);
				m_regionsMappedIntoMemory.push_back(r);
			}
			m_stubIslandRegions.clear();
			for (auto& siV : m_activeDeserContext.doc["stubIslands"].GetArray())
			{
				MemoryRegion si;
				si.LoadFromValue(siV);
				m_stubIslandRegions.push_back(si);
			}
			m_dyldDataRegions.clear();
			for (auto& siV : m_activeDeserContext.doc["dyldDataSections"].GetArray())
			{
				MemoryRegion si;
				si.LoadFromValue(siV);
				m_dyldDataRegions.push_back(si);
			}
			m_nonImageRegions.clear();
			for (auto& siV : m_activeDeserContext.doc["nonImageRegions"].GetArray())
			{
				MemoryRegion si;
				si.LoadFromValue(siV);
				m_nonImageRegions.push_back(si);
			}

			m_metadataValid = true;
		}

	private:
		Ref<Logger> m_logger;
		/* VIEW STATE BEGIN -- SERIALIZE ALL OF THIS AND STORE IT IN RAW VIEW */

		// Updated as the view is loaded further, more images are added, etc
		DSCViewState m_viewState = DSCViewStateUnloaded;
		std::unordered_map<uint64_t, std::vector<std::pair<uint64_t, std::pair<BNSymbolType, std::string>>>>
			m_exportInfos;
		std::unordered_map<uint64_t, std::vector<std::pair<uint64_t, std::pair<BNSymbolType, std::string>>>>
			m_symbolInfos;
		// ---

		// Serialized once by PerformInitialLoad and available after m_viewState == Loaded
		bool m_metadataValid = false;

		std::string m_baseFilePath;
		SharedCacheFormat m_cacheFormat;

		std::unordered_map<std::string, uint64_t> m_imageStarts;
		std::unordered_map<uint64_t, SharedCacheMachOHeader> m_headers;

		std::vector<CacheImage> m_images;

		std::vector<MemoryRegion> m_regionsMappedIntoMemory;

		std::vector<BackingCache> m_backingCaches;

		std::vector<MemoryRegion> m_stubIslandRegions;
		std::vector<MemoryRegion> m_dyldDataRegions;
		std::vector<MemoryRegion> m_nonImageRegions;

		/* VIEWSTATE END -- NOTHING PAST THIS IS SERIALIZED */

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
		bool LoadImageWithInstallName(std::string installName);
		bool LoadSectionAtAddress(uint64_t address);
		bool LoadImageContainingAddress(uint64_t address);
		std::string NameForAddress(uint64_t address);
		std::string ImageNameForAddress(uint64_t address);
		std::vector<std::string> GetAvailableImages();

		std::vector<MemoryRegion> GetMappedRegions() const;

		std::vector<std::pair<std::string, Ref<Symbol>>> LoadAllSymbolsAndWait();

		std::unordered_map<std::string, uint64_t> AllImageStarts() const { return m_imageStarts; }
		std::unordered_map<uint64_t, SharedCacheMachOHeader> AllImageHeaders() const { return m_headers; }

		std::string SerializedImageHeaderForAddress(uint64_t address);
		std::string SerializedImageHeaderForName(std::string name);

		void FindSymbolAtAddrAndApplyToAddr(uint64_t symbolLocation, uint64_t targetLocation, bool triggerReanalysis);

		std::vector<BackingCache> BackingCaches() const {

			return m_backingCaches;
		}

		DSCViewState State() const { return m_viewState; }

		explicit SharedCache(BinaryNinja::Ref<BinaryNinja::BinaryView> rawView);
		~SharedCache() override;

		std::optional<SharedCacheMachOHeader> LoadHeaderForAddress(
			std::shared_ptr<VM> vm, uint64_t address, std::string installName);
		void InitializeHeader(
			Ref<BinaryView> view, VM* vm, SharedCacheMachOHeader header, std::vector<MemoryRegion*> regionsToLoad);
		void ReadExportNode(std::vector<Ref<Symbol>>& symbolList, SharedCacheMachOHeader& header, DataBuffer& buffer, uint64_t textBase,
			const std::string& currentText, size_t cursor, uint32_t endGuard);
		std::vector<Ref<Symbol>> ParseExportTrie(
			std::shared_ptr<MMappedFileAccessor> linkeditFile, SharedCacheMachOHeader header);
	};


}

void InitDSCViewType();

#endif //SHAREDCACHE_SHAREDCACHE_H

