#pragma once

#include <binaryninjaapi.h>
#include "../core/MetadataSerializable.hpp"
#include "view/macho/machoview.h"
#include "sharedcachecore.h"

using namespace BinaryNinja;

namespace SharedCacheAPI {
	template<class T>
	class SCRefCountObject {
		void AddRefInternal() { m_refs.fetch_add(1); }

		void ReleaseInternal() {
			if (m_refs.fetch_sub(1) == 1)
				delete this;
		}

	public:
		std::atomic<int> m_refs;
		T *m_object;

		SCRefCountObject() : m_refs(0), m_object(nullptr) {}

		virtual ~SCRefCountObject() {}

		T *GetObject() const { return m_object; }

		static T *GetObject(SCRefCountObject *obj) {
			if (!obj)
				return nullptr;
			return obj->GetObject();
		}

		void AddRef() { AddRefInternal(); }

		void Release() { ReleaseInternal(); }

		void AddRefForRegistration() { AddRefInternal(); }
	};


	template<class T, T *(*AddObjectReference)(T *), void (*FreeObjectReference)(T *)>
	class SCCoreRefCountObject {
		void AddRefInternal() { m_refs.fetch_add(1); }

		void ReleaseInternal() {
			if (m_refs.fetch_sub(1) == 1) {
				if (!m_registeredRef)
					delete this;
			}
		}

	public:
		std::atomic<int> m_refs;
		bool m_registeredRef = false;
		T *m_object;

		SCCoreRefCountObject() : m_refs(0), m_object(nullptr) {}

		virtual ~SCCoreRefCountObject() {}

		T *GetObject() const { return m_object; }

		static T *GetObject(SCCoreRefCountObject *obj) {
			if (!obj)
				return nullptr;
			return obj->GetObject();
		}

		void AddRef() {
			if (m_object && (m_refs != 0))
				AddObjectReference(m_object);
			AddRefInternal();
		}

		void Release() {
			if (m_object)
				FreeObjectReference(m_object);
			ReleaseInternal();
		}

		void AddRefForRegistration() { m_registeredRef = true; }

		void ReleaseForRegistration() {
			m_object = nullptr;
			m_registeredRef = false;
			if (m_refs == 0)
				delete this;
		}
	};

	struct DSCMemoryRegion {
		uint64_t vmAddress;
		uint64_t size;
		std::string prettyName;
	};

	struct BackingCacheMapping {
		uint64_t vmAddress;
		uint64_t size;
		uint64_t fileOffset;
	};

	struct BackingCache {
		std::string path;
		bool isPrimary;
		std::vector<BackingCacheMapping> mappings;
	};

	struct DSCImageMemoryMapping {
		std::string filePath;
		std::string name;
		uint64_t vmAddress;
		uint64_t size;
		bool loaded;
		uint64_t rawViewOffset;
	};

	struct DSCImage {
		std::string name;
		uint64_t headerAddress;
		std::vector<DSCImageMemoryMapping> mappings;
	};

	struct DSCSymbol {
		uint64_t address;
		std::string name;
		std::string image;
	};

	using namespace BinaryNinja;
	struct SharedCacheMachOHeader : public SharedCacheCore::MetadataSerializable<SharedCacheMachOHeader> {
		uint64_t textBase = 0;
		uint64_t loadCommandOffset = 0;
		mach_header_64 ident;
		std::string identifierPrefix;
		std::string installName;

		std::vector<std::pair<uint64_t, bool>> entryPoints;
		std::vector<uint64_t> m_entryPoints; //list of entrypoints

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
		std::vector<segment_command_64> segments; //only three types of sections __TEXT, __DATA, __IMPORT
		segment_command_64 linkeditSegment;
		std::vector<section_64> sections;
		std::vector<std::string> sectionNames;

		std::vector<section_64> symbolStubSections;
		std::vector<section_64> symbolPointerSections;

		std::vector<std::string> dylibs;

		build_version_command buildVersion;
		std::vector<build_tool_version> buildToolVersions;

		std::string exportTriePath;

		bool dysymPresent = false;
		bool dyldInfoPresent = false;
		bool exportTriePresent = false;
		bool chainedFixupsPresent = false;
		bool routinesPresent = false;
		bool functionStartsPresent = false;
		bool relocatable = false;

		void Store(SharedCacheCore::SerializationContext& context) const {
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
			MSS(exportTriePath);
			MSS(dysymPresent);
			MSS(dyldInfoPresent);
			MSS(exportTriePresent);
			MSS(chainedFixupsPresent);
			MSS(routinesPresent);
			MSS(functionStartsPresent);
			MSS(relocatable);
		}

		static SharedCacheMachOHeader Load(SharedCacheCore::DeserializationContext& context) {
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


	class SharedCache : public SCCoreRefCountObject<BNSharedCache, BNNewSharedCacheReference, BNFreeSharedCacheReference> {
	public:
		SharedCache(Ref<BinaryView> view);

		BNDSCViewState GetState();
		static BNDSCViewLoadProgress GetLoadProgress(Ref<BinaryView> view);
		static uint64_t FastGetBackingCacheCount(Ref<BinaryView> view);

		bool LoadImageWithInstallName(std::string installName, bool skipObjC = false);
		bool LoadSectionAtAddress(uint64_t addr);
		bool LoadImageContainingAddress(uint64_t addr, bool skipObjC = false);
		std::vector<std::string> GetAvailableImages();
	
		void ProcessObjCSectionsForImageWithInstallName(std::string installName);
		void ProcessAllObjCSections();

		std::vector<DSCSymbol> LoadAllSymbolsAndWait();

		std::string GetNameForAddress(uint64_t address);
		std::string GetImageNameForAddress(uint64_t address);

		std::vector<BackingCache> GetBackingCaches();
		std::vector<DSCImage> GetImages();

		std::optional<SharedCacheMachOHeader> GetMachOHeaderForImage(std::string name);
		std::optional<SharedCacheMachOHeader> GetMachOHeaderForAddress(uint64_t address);

		std::vector<DSCMemoryRegion> GetLoadedMemoryRegions();

		void FindSymbolAtAddrAndApplyToAddr(uint64_t symbolLocation, uint64_t targetLocation, bool triggerReanalysis = true) const;
	};
}