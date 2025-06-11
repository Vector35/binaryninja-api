//
// Created by kat on 5/19/23.
//

#include <binaryninjaapi.h>
#include "KCView.h"
#include "view/macho/machoview.h"
#include "MetadataSerializable.hpp"
#include "../api/kernelcachecore.h"

#ifndef KERNELCACHE_KERNELCACHE_H
#define KERNELCACHE_KERNELCACHE_H

DECLARE_KERNELCACHE_API_OBJECT(BNKernelCache, KernelCache);

namespace KernelCacheCore {

	enum KCViewState
	{
		KCViewStateUnloaded,
		KCViewStateLoaded,
		KCViewStateLoadedWithImages,
	};

	const std::string KernelCacheMetadataTag = "KERNELCACHE-KernelCacheData";

		struct MemoryRegion : public MetadataSerializable<MemoryRegion>
		{
			enum class Type
			{
				Image,
				NonImage,
			};

			std::string prettyName;
			uint64_t start;
			uint64_t size;
			uint64_t fileOffset;
			BNSegmentFlag flags;
			Type type;

			void Store(SerializationContext& context) const
			{
				MSS(prettyName);
				MSS(start);
				MSS(size);
				MSS(fileOffset);
				MSS_CAST(flags, uint64_t);
				MSS_CAST(type, uint8_t);
			}

			static MemoryRegion Load(DeserializationContext& context)
			{
				MemoryRegion region;
				region.MSL(prettyName);
				region.MSL(start);
				region.MSL(size);
				region.MSL(fileOffset);
				region.MSL_CAST(flags, uint64_t, BNSegmentFlag);
				region.MSL_CAST(type, uint8_t, Type);
				return region;
			}
		};

		struct KernelCacheImage : public MetadataSerializable<KernelCacheImage> {
			std::string installName;
			uint64_t headerFileLocation;
			std::vector<MemoryRegion> regions;

			void Store(SerializationContext& context) const;
			static KernelCacheImage Load(DeserializationContext& context);
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

	#if defined(_MSC_VER)
		#pragma pack(pop)
	#else

	#endif

	using namespace BinaryNinja;
	struct KernelCacheMachOHeader : public MetadataSerializable<KernelCacheMachOHeader>
	{
		uint64_t textBase = 0;
		uint64_t textBaseFileOffset = 0;
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
		std::vector<section_64> moduleTermSections;
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
			MSS(textBaseFileOffset);
			MSS(loadCommandOffset);
			MSS_SUBCLASS(ident);
			MSS(identifierPrefix);
			MSS(installName);
			MSS(entryPoints);
			MSS(m_entryPoints);
			MSS_SUBCLASS(symtab);
			MSS_SUBCLASS(dysymtab);
			MSS_SUBCLASS(dyldInfo);
			MSS_SUBCLASS(routines64);
			MSS_SUBCLASS(functionStarts);
			MSS_SUBCLASS(moduleInitSections);
			MSS_SUBCLASS(moduleTermSections);
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
			MSS(dysymPresent);
			MSS(dyldInfoPresent);
			MSS(exportTriePresent);
			MSS(chainedFixupsPresent);
			MSS(routinesPresent);
			MSS(functionStartsPresent);
			MSS(relocatable);
		}

		static KernelCacheMachOHeader Load(DeserializationContext& context) {
			KernelCacheMachOHeader header;
			header.MSL(textBase);
			header.MSL(textBaseFileOffset);
			header.MSL(loadCommandOffset);
			header.MSL(ident);
			header.MSL(identifierPrefix);
			header.MSL(installName);
			header.MSL(entryPoints);
			header.MSL(m_entryPoints);
			header.MSL(symtab);
			header.MSL(dysymtab);
			header.MSL(dyldInfo);
			header.MSL(routines64);
			header.MSL(functionStarts);
			header.MSL(moduleInitSections);
			header.MSL(moduleTermSections);
			header.MSL(exportTrie);
			header.MSL(chainedFixups);
			header.MSL(relocationBase);
			header.MSL(segments);
			header.MSL(linkeditSegment);
			header.MSL(sections);
			header.MSL(sectionNames);
			header.MSL(symbolStubSections);
			header.MSL(symbolPointerSections);
			header.MSL(dylibs);
			header.MSL(buildVersion);
			header.MSL(buildToolVersions);
			header.MSL(linkeditPresent);
			header.MSL(dysymPresent);
			header.MSL(dyldInfoPresent);
			header.MSL(exportTriePresent);
			header.MSL(chainedFixupsPresent);
			header.MSL(routinesPresent);
			header.MSL(functionStartsPresent);
			header.MSL(relocatable);
			return header;
		}
	};

	class KernelCache : public MetadataSerializable<KernelCache>
	{
		IMPLEMENT_KERNELCACHE_API_OBJECT(BNKernelCache);

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
		enum KernelCacheFormat
		{
			FilesetCacheFormat,
			PrelinkedCacheFormat,
		};

		struct CacheInfo;
		struct ModifiedState;

		struct ViewSpecificState;

		void Store(SerializationContext& context) const;
		void Load(DeserializationContext& context);

	private:
		Ref<Logger> m_logger;
		/* VIEW STATE BEGIN -- SERIALIZE ALL OF THIS AND STORE IT IN RAW VIEW */

		// State that is initialized during `PerformInitialLoad` and does
		// not change thereafter.
		std::shared_ptr<const CacheInfo> m_cacheInfo;

		// Protects member variables below.
		mutable std::mutex m_mutex;

		// State that has been modified since this instance was created
		// or last saved to the view-specific state.
		// To get an accurate view of the current state, both these modifications
		// and the view-specific state must be consulted.
		std::unique_ptr<ModifiedState> m_modifiedState;

		// Serialized once by PerformInitialLoad and available after m_viewState == Loaded
		bool m_metadataValid = false;

		/* API VIEW START */
		BinaryNinja::Ref<BinaryNinja::BinaryView> m_kcView;
		/* API VIEW END */

		std::shared_ptr<ViewSpecificState> m_viewSpecificState;

	private:
		void PerformInitialLoad(std::lock_guard<std::mutex>&);
		void DeserializeFromRawView(std::lock_guard<std::mutex>&);

	public:
		static KernelCache* GetFromKCView(BinaryNinja::Ref<BinaryNinja::BinaryView> kcView);
		static uint64_t FastGetImageCount(BinaryNinja::Ref<BinaryNinja::BinaryView> kcView);
		bool SaveCacheInfoToKCView(std::lock_guard<std::mutex>&);
		bool SaveModifiedStateToKCView(std::lock_guard<std::mutex>&);
		std::optional<uint64_t> GetImageStart(std::string installName);
		std::optional<KernelCacheMachOHeader> HeaderForVMAddress(uint64_t address);
		std::optional<KernelCacheMachOHeader> HeaderForFileAddress(uint64_t address);
		bool LoadImageWithInstallName(std::lock_guard<std::mutex>& lock, std::string installName);
		bool LoadImageWithInstallName(std::string installName);
		bool LoadImageContainingAddress(std::lock_guard<std::mutex>& lock, uint64_t address);
		bool LoadImageContainingAddress(uint64_t address);
		std::string NameForAddress(uint64_t address);
		std::string ImageNameForAddress(uint64_t address);
		std::vector<std::string> GetAvailableImages();
		std::vector<KernelCacheImage> GetLoadedImages();
		bool IsImageLoaded(uint64_t address);

		std::vector<std::pair<uint64_t, std::pair<std::string, std::string>>> LoadAllSymbolsAndWait();

		const std::unordered_map<std::string, uint64_t>& AllImageStarts() const;
		const std::unordered_map<uint64_t, KernelCacheMachOHeader> AllImageHeaders() const;

		std::string SerializedImageHeaderForVMAddress(uint64_t address);
		std::string SerializedImageHeaderForName(std::string name);

		KCViewState ViewState() const;

		explicit KernelCache(BinaryNinja::Ref<BinaryNinja::BinaryView> rawView);
		virtual ~KernelCache();

		static bool InitializeSegmentsForHeader(Ref<BinaryView> view, const KernelCacheMachOHeader& header, const KernelCacheImage& targetImage);
		static std::optional<KernelCacheMachOHeader> LoadHeaderForAddress(Ref<BinaryView> view, uint64_t address, std::string installName);
		static void InitializeHeader(Ref<BinaryView> view, KernelCacheMachOHeader header);
		static void ReadExportNode(Ref<BinaryView> view, std::vector<Ref<Symbol>>& symbolList, KernelCacheMachOHeader& header, DataBuffer& buffer,
			uint64_t textBase, const std::string& currentText, size_t cursor, uint32_t endGuard);
		static std::vector<Ref<Symbol>> ParseExportTrie(Ref<BinaryView> view, KernelCacheMachOHeader header);
		static std::vector<std::pair<uint64_t, std::pair<BNSymbolType, std::string>>> ParseSymbolTable(Ref<BinaryView> view, KernelCacheMachOHeader header, bool defineSymbolsInView = true);
	};


	class KernelCacheMetadata
	{
	public:
		static std::optional<KernelCacheMetadata> LoadFromView(BinaryView*);
		static bool ViewHasMetadata(BinaryView*);

		std::string InstallNameForImageBaseAddress(uint64_t baseAddress) const;

		std::vector<KernelCacheImage> LoadedImages();

		~KernelCacheMetadata();
		KernelCacheMetadata(KernelCacheMetadata&&);
		KernelCacheMetadata& operator=(KernelCacheMetadata&&);

	private:
		KernelCacheMetadata(KernelCache::CacheInfo, KernelCache::ModifiedState);

		std::unique_ptr<KernelCache::CacheInfo> cacheInfo;
		std::unique_ptr<KernelCache::ModifiedState> state;

		friend struct KernelCache::ModifiedState;
		friend class KernelCache;

		static const std::string Tag;
		static const std::string CacheInfoTag;
		static const std::string ModifiedStateTagPrefix;
		static const std::string ModifiedStateCountTag;
	};

}

void InitKernelcache();

#endif //KERNELCACHE_KERNELCACHE_H

