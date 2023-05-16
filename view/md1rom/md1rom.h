#include "binaryninjaapi.h"

namespace BinaryNinja
{
	const uint32_t MAGIC_1 = 0x58881688;
	const uint32_t MAGIC_2 = 0x58891689;

	struct Md1romSegmentHeader
	{
		uint32_t magic;
		uint32_t length;
		std::string name;
		uint32_t addr;
		uint32_t mode;
		uint32_t magic2;
		uint32_t offset;
//		uint32_t unk1;
//		uint32_t unk2;
//		uint32_t unk3;
//		uint32_t unk4;
//		uint32_t unk5;
//		uint32_t unk6;
	};

	class Md1romView: public BinaryView
	{
		bool m_parseOnly;
		uint64_t m_entryPoint{};
		BNEndianness m_endian;
		size_t m_addressSize;
		Ref<Architecture> m_arch;
		Ref<Platform> m_plat = nullptr;
		Ref<Logger> m_logger;
		bool m_relocatable = false;

		std::vector<Md1romSegmentHeader> m_headers;

		SymbolQueue* m_symbolQueue = nullptr;

		virtual uint64_t PerformGetEntryPoint() const override;

		virtual bool PerformIsExecutable() const override { return true; }
		virtual BNEndianness PerformGetDefaultEndianness() const override;
		virtual bool PerformIsRelocatable() const override;
		virtual size_t PerformGetAddressSize() const override;

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
