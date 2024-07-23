#pragma once

#include "binaryninjaapi.h"

#ifdef WIN32
#pragma warning(disable: 4005)
#endif

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
	VxWorks5PowerPCLocalSDASymbolType = 0x40,
	VxWorks5PowerPCGlobalSDASymbolType = 0x41,
	VxWorks5PowerPCLocalSDA2SymbolType = 0x80,
	VxWorks5PowerPCGlobalSDA2SymbolType = 0x81,
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
	VxWorks6GlobalSymbols = 0x41,
};

struct VxWorksSymbolEntry
{
	uint32_t name;
	uint32_t address;
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
		Ref<BinaryView> m_parentView = nullptr;
		BNEndianness m_endianness = BigEndian;
		Ref<Platform> m_platform;
		Ref<Architecture> m_arch;
		size_t m_addressSize;
		bool m_hasSymbolTable = false;
		uint64_t m_symbolTableOffset = 0;
		uint64_t m_entryPoint = 0;
		uint64_t m_determinedImageBase = 0; // Determined from analysis of the symbol table
		uint64_t m_imageBase = 0; // Selected image base that could be overriden by user
		std::vector<VxWorksSectionInfo> m_sections;
		VxWorksVersion m_version = VxWorksUnknownVersion;
		std::vector<VxWorksSymbolEntry> m_symbols;

	private:
		bool IsASCIIString(std::string &s);
		void DefineSymbolTableDataVariable();
		uint64_t FindSysInit(BinaryReader *reader, uint64_t imageBase);
		void AdjustImageBaseForHeaderIfPresent(BinaryReader* reader);
		void DetermineImageBaseFromSymbols(BinaryReader* reader);
		void AssignSymbolToSection(std::map<std::string, std::set<uint64_t>>& sections,
			BNSymbolType bnSymbolType, uint8_t vxSymbolType, uint64_t address);
		void ProcessSymbolTable(BinaryReader *reader);
		void AddSections();

	protected:
		virtual uint64_t PerformGetStart() const override;
		virtual uint64_t PerformGetEntryPoint() const override;
		virtual bool PerformIsExecutable() const override { return true; }
		virtual BNEndianness PerformGetDefaultEndianness() const override { return m_endianness; }
		virtual bool PerformIsRelocatable() const override { return m_hasSymbolTable == false; }
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
