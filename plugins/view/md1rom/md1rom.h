#include "binaryninjaapi.h"

namespace BinaryNinja
{
	const uint32_t MAGIC_1 = 0x58881688;
	const uint32_t MAGIC_2 = 0x58891689;
	const uint64_t MAIN_ROM_BASE = 0x90000000;

	struct Md1romSegment
	{
		uint32_t magic;
		uint32_t length;
		std::string name;
		uint32_t addr;
		uint32_t mode;
		uint32_t magic2;
		uint32_t offset;
		// start of the header in the raw view
		uint32_t headerStart;

		// start of the data in the raw view
		uint32_t dataStart;
	};

	struct Md1DebugSymbol
	{
		std::string name;
		uint32_t start;
		uint32_t end;
	};

	struct CATDEntryHeader
	{
		uint32_t unknown;
		uint32_t offset;
		uint32_t size;
	};

	struct CATDEntry
	{
		uint32_t offset;
		uint32_t size;
		uint32_t uncompressedSize;
	};

	class Md1romView: public BinaryView
	{
		bool m_parseOnly;
		uint64_t m_entryPoint{};
		BNEndianness m_endian = LittleEndian;
		size_t m_addressSize = 4;
		Ref<Architecture> m_arch = nullptr;
		Ref<Platform> m_plat = nullptr;
		Ref<Logger> m_logger;
		bool m_relocatable = false;

		std::vector<Md1romSegment> m_segments;
		std::vector<Md1DebugSymbol> m_debugSymbols;
		std::vector<CATDEntryHeader> m_catdEntryHeaders;
		std::vector<CATDEntry> m_catdEntries;

		bool m_mainRomFound = false, m_dbgInfoFound = false, m_dbgDbFound = false;
		Md1romSegment m_mainRom, m_dbgInfoSeg, m_dbgDatabaseSeg;

		SymbolQueue* m_symbolQueue = nullptr;

		virtual uint64_t PerformGetEntryPoint() const override;

		virtual bool PerformIsExecutable() const override { return true; }
		virtual BNEndianness PerformGetDefaultEndianness() const override;
		virtual bool PerformIsRelocatable() const override;
		virtual size_t PerformGetAddressSize() const override;

		void ParseDebugInfo();
		void ParseDebugDatabase();
		void DefineMd1RomSymbol(BNSymbolType type, const std::string& name, uint64_t addr,
							 	BNSymbolBinding binding=NoBinding, Ref<Type> typeObj=nullptr);

	public:
		Md1romView(BinaryView* data, bool parseOnly = false);
		~Md1romView();

		virtual bool Init() override;
	};

	class Md1romViewType: public BinaryViewType
	{
		Ref<Logger> m_logger;
	public:
		Md1romViewType();
		virtual Ref<BinaryView> Create(BinaryView* data) override;
		virtual Ref<BinaryView> Parse(BinaryView* data) override;
		virtual bool IsTypeValidForData(BinaryView* data) override;
		virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) override;
	};

	void InitMd1romViewType();
}
