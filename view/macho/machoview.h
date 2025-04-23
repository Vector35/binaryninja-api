#pragma once

#include <exception>
#include <vector>
#include <string.h>

#include "binaryninjaapi.h"
#include "objc.h"
#include "macho/types.h"

#define SECTION_TYPE		 0x000000ff	/* 256 section types */
#define SECTION_ATTRIBUTES	 0xffffff00	/*  24 section attributes */

#define BINARYNINJA_MANUAL_RELOCATION ((uint64_t)-2)

namespace BinaryNinja {

	// When we preload the table, we store them in this format.
	struct import_entry
	{
		uint64_t lib_ordinal;
		uint64_t addend;
		bool weak;
		std::string name;
	};

	struct MachOHeader {
		bool isMainHeader = false;

		uint64_t textBase = 0;
		uint64_t loadCommandOffset = 0;
		mach_header_64 ident;
		std::string identifierPrefix;

		std::vector<std::pair<uint64_t, bool>> entryPoints;
		std::vector<uint64_t> m_entryPoints; //list of entrypoints

		std::vector<std::pair<BNRelocationInfo, std::string>> externalRelocations;
		std::vector<BNRelocationInfo> rebaseRelocations;

		symtab_command symtab;
		dysymtab_command dysymtab;
		dyld_info_command dyldInfo;
		routines_command_64 routines64;
		function_starts_command functionStarts;
		std::vector<section_64> moduleInitSections;
		linkedit_data_command exportTrie;
		linkedit_data_command chainedFixups {};
		section_64 chainStarts {};

		DataBuffer* stringList;
		size_t stringListSize = 0;

		uint64_t relocationBase = 0;
		// Section and program headers, internally use 64-bit form as it is a superset of 32-bit
		std::vector<segment_command_64> segments; //only three types of sections __TEXT, __DATA, __IMPORT
		std::vector<section_64> sections;
		std::vector<std::string> sectionNames;

		std::vector<section_64> symbolStubSections;
		std::vector<section_64> symbolPointerSections;

		std::vector<std::pair<std::string, std::string>> dylibs;

		build_version_command buildVersion;
		std::vector<build_tool_version> buildToolVersions;

		bool dysymPresent = false;
		bool dyldInfoPresent = false;
		bool exportTriePresent = false;
		bool chainedFixupsPresent = false;
		bool chainStartsPresent = false;
		bool routinesPresent = false;
		bool functionStartsPresent = false;
		bool relocatable = false;
	};

	class MachoView: public BinaryView
	{
		MachOHeader m_header;
		std::map<uint64_t, MachOHeader> m_subHeaders; // Used for MH_FILESET entries.

		MachoObjCProcessor* m_objcProcessor = nullptr;

		uint64_t m_universalImageOffset;
		bool m_parseOnly, m_backedByDatabase;
		int64_t m_imageBaseAdjustment;
		size_t m_addressSize;	 //Address size in bytes 4/8
		BNEndianness m_endian;
		uint32_t m_archId;
		Ref<Architecture> m_arch;
		Ref<Platform> m_plat = nullptr;
		bool m_dylibFile;
		bool m_objectFile;
		std::vector<std::string> m_symbols;

		bool m_relocatable = false;

		bool m_extractMangledTypes;
		bool m_simplifyTemplates;

		SymbolQueue* m_symbolQueue = nullptr;
		Ref<Logger> m_logger;

		std::vector<segment_command_64> m_allSegments; //only three types of sections __TEXT, __DATA, __IMPORT
		std::vector<section_64> m_allSections;

		MachOHeader HeaderForAddress(BinaryView* data, uint64_t address, bool isMainHeader, std::string identifierPrefix = "");
		bool InitializeHeader(MachOHeader& header, bool isMainHeader, uint64_t preferredImageBase,
			std::string preferredImageBaseDesc, bool platformSetByUser);

		void RebaseThreadStarts(BinaryReader& virtualReader, std::vector<uint32_t>& threadStarts, uint64_t stepMultiplier);
		Ref<Symbol> DefineMachoSymbol(
			BNSymbolType type, const std::string& name, uint64_t addr, BNSymbolBinding binding, bool deferred);
		void ParseSymbolTable(BinaryReader& reader, MachOHeader& header, const symtab_command& symtab, const std::vector<uint32_t>& symbolStubsList);
		bool IsValidFunctionStart(uint64_t addr);
		void ParseFunctionStarts(Platform* platform, uint64_t textBase, function_starts_command functionStarts);
		bool ParseRelocationEntry(const relocation_info& info, uint64_t start, BNRelocationInfo& result);

		bool AddExportTerminalSymbol(const std::string& symbolName, uint64_t symbolFlags, uint64_t imageOffset);
		void ParseExportTrie(BinaryReader& reader, linkedit_data_command exportTrie);
		void ReadExportNode(uint64_t viewStart, DataBuffer& buffer, const std::string& currentText,
			size_t cursor, uint32_t endGuard);

		void ParseRebaseTable(BinaryReader& reader, MachOHeader& header, uint32_t tableOffset, uint32_t tableSize);
		void ParseDynamicTable(BinaryReader& reader, MachOHeader& header, BNSymbolType type, uint32_t tableOffset, uint32_t tableSize,
			BNSymbolBinding binding);
		bool GetSectionPermissions(MachOHeader& header, uint64_t address, uint32_t &flags);
		bool GetSegmentPermissions(MachOHeader& header, uint64_t address, uint32_t &flags);
		void ParseChainedFixups(MachOHeader& header, linkedit_data_command chainedFixups);
		void ParseChainedStarts(MachOHeader& header, section_64 chainedStarts);

		virtual uint64_t PerformGetEntryPoint() const override;

		virtual bool PerformIsExecutable() const override { return true; }
		virtual BNEndianness PerformGetDefaultEndianness() const override;
		virtual bool PerformIsRelocatable() const override;
		virtual size_t PerformGetAddressSize() const override;
	public:
		MachoView(const std::string& typeName, BinaryView* data, bool parseOnly = false);

		virtual bool Init() override;
	};

	class MachoViewType: public BinaryViewType
	{
		Ref<Logger> m_logger;
	public:
		MachoViewType();
		virtual Ref<BinaryView> Create(BinaryView* data) override;
		virtual Ref<BinaryView> Parse(BinaryView* data) override;
		virtual bool IsTypeValidForData(BinaryView* data) override;
		virtual uint64_t ParseHeaders(BinaryView* data, uint64_t imageOffset, mach_header_64& ident, Ref<Architecture>* arch, Ref<Platform>* platform, std::string& errorMsg);
		virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) override;
	};

	void InitMachoViewType();
}  // namespace BinaryNinja
