#pragma once

#include "binaryninjaapi.h"

#ifdef WIN32
#pragma warning(disable: 4005)
#endif

#define DEFAULT_VXWORKS_BASE_ADDRESS 0x10000
#define MAX_SYMBOL_TABLE_REGION_SIZE 0x2000000
#define MIN_VALID_SYMBOL_ENTRIES 256
#define VXWORKS_SYMBOL_ENTRY_TYPE(flags) ((flags >> 8) & 0xff)

enum VxWorksVersion
{
	VxWorksUnknownVersion,
	VxWorksVersion5,
	VxWorksVersion6,
};

enum VxWorksImageType
{
	VxWorksUnsupportedImageType,
	VxWorksStandardImageType,
	VxWorksCDMPackagedImageType,
	VxWorksCDMNewImageType,
};

enum VxWorks5SymbolType
{
	VxWorks5UndefinedSymbolType = 0x00,
	VxWorks5GlobalExternalSymbolType = 0x01,
	VxWorks5LocalAbsoluteSymbolType = 0x02,
	VxWorks5GlobalAbsoluteSymbolType = 0x03,
	VxWorks5LocalTextSymbolType = 0x04,
	VxWorks5GlobalTextSymbolType = 0x05,
	VxWorks5LocalDataSymbolType = 0x06,
	VxWorks5GlobalDataSymbolType = 0x07,
	VxWorks5LocalBSSSymbolType = 0x08,
	VxWorks5GlobalBSSSymbolType = 0x09,
	VxWorks5LocalCommonSymbolType = 0x12,
	VxWorks5GlobalCommonSymbolType = 0x13,
};

std::map<VxWorks5SymbolType, BNSymbolType> VxWorks5SymbolTypeMap = {
	{ VxWorks5UndefinedSymbolType, FunctionSymbol },
	{ VxWorks5GlobalExternalSymbolType, ImportAddressSymbol },
	{ VxWorks5LocalAbsoluteSymbolType, DataSymbol },
	{ VxWorks5GlobalAbsoluteSymbolType, DataSymbol },
	{ VxWorks5LocalTextSymbolType, FunctionSymbol },
	{ VxWorks5GlobalTextSymbolType, FunctionSymbol },
	{ VxWorks5LocalDataSymbolType, DataSymbol },
	{ VxWorks5GlobalDataSymbolType, DataSymbol },
	{ VxWorks5LocalBSSSymbolType, DataSymbol },
	{ VxWorks5GlobalBSSSymbolType, DataSymbol },
	{ VxWorks5LocalCommonSymbolType, DataSymbol },
	{ VxWorks5GlobalCommonSymbolType, DataSymbol },
};

enum VxWorks6SymbolType
{
	VxWorks6UndefinedSymbolType = 0x00,
	VxWorks6GlobalExternalSymbolType = 0x01,
	VxWorks6LocalAbsoluteSymbolType = 0x02,
	VxWorks6GlobalAbsoluteSymbolType = 0x03,
	VxWorks6LocalTextSymbolType = 0x04,
	VxWorks6GlobalTextSymbolType = 0x05,
	VxWorks6LocalDataSymbolType = 0x08,
	VxWorks6GlobalDataSymbolType = 0x09,
	VxWorks6LocalBSSSymbolType = 0x10,
	VxWorks6GlobalBSSSymbolType = 0x11,
	VxWorks6LocalCommonSymbolType = 0x20,
	VxWorks6GlobalCommonSymbolType = 0x21,
	VxWorks6LocalSymbols = 0x40,
	VxWorks6GlobalSymboks = 0x41,
};

std::map<VxWorks6SymbolType, BNSymbolType> VxWorks6SymbolTypeMap = {
	{ VxWorks6UndefinedSymbolType, FunctionSymbol },
	{ VxWorks6GlobalExternalSymbolType, ImportAddressSymbol },
	{ VxWorks6LocalAbsoluteSymbolType, DataSymbol },
	{ VxWorks6GlobalAbsoluteSymbolType, DataSymbol },
	{ VxWorks6LocalTextSymbolType, FunctionSymbol },
	{ VxWorks6GlobalTextSymbolType, FunctionSymbol },
	{ VxWorks6LocalDataSymbolType, DataSymbol },
	{ VxWorks6GlobalDataSymbolType, DataSymbol },
	{ VxWorks6LocalBSSSymbolType, DataSymbol },
	{ VxWorks6GlobalBSSSymbolType, DataSymbol },
	{ VxWorks6LocalCommonSymbolType, DataSymbol },
	{ VxWorks6GlobalCommonSymbolType, DataSymbol },
	{ VxWorks6LocalSymbols, DataSymbol },
	{ VxWorks6GlobalSymboks, DataSymbol },
};

struct VxWorks5SymbolTableEntry
{
	uint32_t unknown;
	uint32_t name;
	uint32_t address;
	uint32_t flags;
};

struct VxWorks6SymbolTableEntry
{
	uint32_t unknown1;
	uint32_t name;
	uint32_t address;
	uint32_t unknown2;
	uint32_t flags;
};

struct VxWorksSectionInfo
{
	std::pair<uint64_t, uint64_t> AddressRange;
	std::string Name;
	BNSectionSemantics Semantics;
};

namespace BinaryNinja
{
	class VxWorksView: public BinaryView
	{
		Ref<Logger> m_logger;
		bool m_parseOnly;
		bool m_relocatable = false;
		BNEndianness m_endianness = BigEndian;
		Ref<Platform> m_platform;
		Ref<Architecture> m_arch;
		size_t m_addressSize;
		uint64_t m_entryPoint = 0;
		uint64_t m_imageBase = 0;
		uint64_t m_sysInit = 0; // Entrypoint, if we find it in the symbol table
		std::vector<VxWorksSectionInfo> m_sections;

		VxWorksVersion m_version = VxWorksUnknownVersion;
		std::vector<VxWorks5SymbolTableEntry> m_symbolTable5;
		std::vector<VxWorks6SymbolTableEntry> m_symbolTable6;

	private:
		void DetermineEntryPoint();
		void AddSections(BinaryView* parentView);
		void ProcessSymbolTable(BinaryReader *reader);
		bool ScanForVxWorks6SymbolTable(BinaryView* parentView, BinaryReader *reader);
		bool ScanForVxWorks5SymbolTable(BinaryView* parentView, BinaryReader *reader);
		bool ScanForVxWorksSymbolTable(BinaryView* parentView, BinaryReader *reader);
		void DetermineImageBaseFromSymbols();

	protected:
		virtual uint64_t PerformGetEntryPoint() const override;
		virtual bool PerformIsExecutable() const override { return true; }
		virtual BNEndianness PerformGetDefaultEndianness() const override { return m_endianness; }
		virtual bool PerformIsRelocatable() const override { return m_relocatable; }
		virtual size_t PerformGetAddressSize() const override;

	public:
		VxWorksView(BinaryView* data, bool parseOnly = false);
		virtual bool Init() override;
	}; // class VxWorksView

	class VxWorksViewType: public BinaryViewType
	{
		Ref<Logger> m_logger;


	public:
		VxWorksViewType();
		virtual Ref<BinaryView> Create(BinaryView* data) override;
		virtual Ref<BinaryView> Parse(BinaryView* data) override;
		virtual bool IsTypeValidForData(BinaryView* data) override;
		virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) override;
		static enum VxWorksImageType IdentifyImageType(Ref<BinaryReader>& reader);
	}; // class VxWorksViewType

	void InitVxWorksViewType();
} // namespace BinaryNinja
