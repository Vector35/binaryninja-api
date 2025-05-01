#pragma once

#include <binaryninjaapi.h>
#include "../core/MetadataSerializable.hpp"
#include "../api/view/macho/machoview.h"
#include "kernelcachecore.h"

using namespace BinaryNinja;

namespace KernelCacheAPI {
	template<class T>
	class KCRefCountObject {
		void AddRefInternal() { m_refs.fetch_add(1); }

		void ReleaseInternal() {
			if (m_refs.fetch_sub(1) == 1)
				delete this;
		}

	public:
		std::atomic<int> m_refs;
		T *m_object;

		KCRefCountObject() : m_refs(0), m_object(nullptr) {}

		virtual ~KCRefCountObject() {}

		T *GetObject() const { return m_object; }

		static T *GetObject(KCRefCountObject *obj) {
			if (!obj)
				return nullptr;
			return obj->GetObject();
		}

		void AddRef() { AddRefInternal(); }

		void Release() { ReleaseInternal(); }

		void AddRefForRegistration() { AddRefInternal(); }
	};


	template<class T, T *(*AddObjectReference)(T *), void (*FreeObjectReference)(T *)>
	class KCCoreRefCountObject {
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

		KCCoreRefCountObject() : m_refs(0), m_object(nullptr) {}

		virtual ~KCCoreRefCountObject() {}

		T *GetObject() const { return m_object; }

		static T *GetObject(KCCoreRefCountObject *obj) {
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

	struct KCMemoryRegion {
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

	struct KCImageMemoryMapping {
		std::string name;
		uint64_t vmAddress;
		uint64_t size;
		bool loaded;
		uint64_t rawViewOffset;
	};

	struct KCImage {
		std::string name;
		uint64_t headerFileAddress;
		std::vector<KCImageMemoryMapping> mappings;
	};

	struct KCSymbol {
		uint64_t address;
		std::string name;
		std::string image;
	};

	using namespace BinaryNinja;
	struct KernelCacheMachOHeader : public KernelCacheCore::MetadataSerializable<KernelCacheMachOHeader> {
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

		bool dysymPresent = false;
		bool dyldInfoPresent = false;
		bool exportTriePresent = false;
		bool chainedFixupsPresent = false;
		bool routinesPresent = false;
		bool functionStartsPresent = false;
		bool relocatable = false;

		void Store(KernelCacheCore::SerializationContext& context) const {
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
			MSS_SUBCLASS(routines64);
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
			MSS(dysymPresent);
			MSS(dyldInfoPresent);
			MSS(exportTriePresent);
			MSS(chainedFixupsPresent);
			MSS(routinesPresent);
			MSS(functionStartsPresent);
			MSS(relocatable);
		}

		static KernelCacheMachOHeader Load(KernelCacheCore::DeserializationContext& context) {
			KernelCacheMachOHeader header;
			header.MSL(textBase);
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


	class KernelCache : public KCCoreRefCountObject<BNKernelCache, BNNewKernelCacheReference, BNFreeKernelCacheReference> {
	public:
		KernelCache(Ref<BinaryView> view);

		BNKCViewState GetState();
		static BNKCViewLoadProgress GetLoadProgress(Ref<BinaryView> view);
		static uint64_t FastGetImageCount(Ref<BinaryView> view);

		bool LoadImageWithInstallName(std::string installName);
		bool LoadImageContainingAddress(uint64_t addr);
		std::vector<std::string> GetAvailableImages();

		bool IsImageLoaded(const uint64_t address) const;

		std::vector<KCSymbol> LoadAllSymbolsAndWait();

		std::string GetNameForAddress(uint64_t address);
		std::string GetImageNameForAddress(uint64_t address);

		std::vector<KCImage> GetImages();
		std::vector<KCImage> GetLoadedImages();

		std::optional<KernelCacheMachOHeader> GetMachOHeaderForImage(std::string name);
		std::optional<KernelCacheMachOHeader> GetMachOHeaderForAddress(uint64_t address);
	};
}