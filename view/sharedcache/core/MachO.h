#pragma once

#include "VirtualMemory.h"

// TODO: Including this adds a bunch of binary ninja specific stuff :ugh:
#include "view/macho/machoview.h"

struct CacheSymbol;

// Used when reading symbol/string table info.
struct TableInfo
{
	// VM address where the reading will begin.
	uint64_t address;
	// Number of entries in the table.
	uint32_t entries;
};

struct SharedCacheMachOHeader
{
	uint64_t textBase = 0;
	uint64_t loadCommandOffset = 0;
	BinaryNinja::mach_header_64 ident;
	// NOTE: This should never be empty.
	std::string identifierPrefix;
	std::string installName;

	std::vector<std::pair<uint64_t, bool>> entryPoints;
	std::vector<uint64_t> m_entryPoints;  // list of entrypoints

	BinaryNinja::symtab_command symtab;
	BinaryNinja::dysymtab_command dysymtab;
	BinaryNinja::dyld_info_command dyldInfo;
	BinaryNinja::routines_command_64 routines64;
	BinaryNinja::function_starts_command functionStarts;
	std::vector<BinaryNinja::section_64> moduleInitSections;
	BinaryNinja::linkedit_data_command exportTrie;
	BinaryNinja::linkedit_data_command chainedFixups {};

	uint64_t relocationBase;
	// Section and program headers, internally use 64-bit form as it is a superset of 32-bit
	std::vector<BinaryNinja::segment_command_64> segments;  // only three types of sections __TEXT, __DATA, __IMPORT
	BinaryNinja::segment_command_64 linkeditSegment;
	std::vector<BinaryNinja::section_64> sections;
	std::vector<std::string> sectionNames;

	std::vector<BinaryNinja::section_64> symbolStubSections;
	std::vector<BinaryNinja::section_64> symbolPointerSections;

	std::vector<std::string> dylibs;

	BinaryNinja::build_version_command buildVersion;
	std::vector<BinaryNinja::build_tool_version> buildToolVersions;

	std::string exportTriePath;

	bool linkeditPresent = false;
	bool dysymPresent = false;
	bool dyldInfoPresent = false;
	bool exportTriePresent = false;
	bool chainedFixupsPresent = false;
	bool routinesPresent = false;
	bool functionStartsPresent = false;
	bool relocatable = false;

	// The base address of the link edit file.
	// Use this if you want to read offsets relative to the file containing the link edit segment.
	uint64_t GetLinkEditFileBase() const { return linkeditSegment.vmaddr - linkeditSegment.fileoff; };

	static std::optional<SharedCacheMachOHeader> ParseHeaderForAddress(
		std::shared_ptr<VirtualMemory> vm, uint64_t address, const std::string& imagePath);

	std::vector<CacheSymbol> ReadSymbolTable(VirtualMemory& vm, const TableInfo &symbolInfo, const TableInfo &stringInfo) const;

	bool AddExportTerminalSymbol(
		std::vector<CacheSymbol>& symbols, const std::string& symbolName, const uint8_t* current,
		const uint8_t* end) const;

	bool ProcessLinkEditTrie(std::vector<CacheSymbol>& symbols, const std::string& currentText, const uint8_t* begin,
		const uint8_t* current, const uint8_t* end) const;

	std::vector<CacheSymbol> ReadExportSymbolTrie(VirtualMemory& vm) const;

	std::vector<uint64_t> ReadFunctionTable(VirtualMemory& vm) const;
};
