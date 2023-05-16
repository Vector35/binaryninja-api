#include "md1rom.h"

using namespace BinaryNinja;

static Md1romViewType* g_md1romViewType = nullptr;


void BinaryNinja::InitMd1romViewType()
{
	static Md1romViewType type;
	BinaryViewType::Register(&type);
	g_md1romViewType = &type;
}


Md1romView::Md1romView(BinaryNinja::BinaryView* data, bool parseOnly): BinaryView("MD1ROM", data->GetFile(), data),
	m_parseOnly(parseOnly)
{
	BinaryReader reader(data);
	uint64_t offset = 0;
	try
	{
		while (true)
		{
			Md1romSegmentHeader seg;
			reader.Seek(offset);
			seg.magic = reader.Read32();
			seg.length = reader.Read32();
			DataBuffer name = reader.Read(0x20);
			size_t nameLen = name.GetData() ? strlen((char*)name.GetData()) : 0;
			if (nameLen)
				seg.name = std::string((char*)name.GetData(), nameLen);

			seg.addr = reader.Read32();
			seg.mode = reader.Read32();
			seg.magic2 = reader.Read32();
			seg.offset = reader.Read32();

			if ((seg.magic != MAGIC_1) || (seg.magic2 != MAGIC_2))
				break;

			m_headers.emplace_back(seg);
			LogWarn("segment: %s, offset: 0x%x, length: 0x%x, addr: 0x%x, file offset: 0x%llx",
				seg.name.c_str(), seg.offset, seg.length, seg.addr, offset);

			offset += (seg.length + seg.offset);
			if (offset % 0x10 != 0)
				offset = offset - offset % 0x10 + 0x10;

			if (offset >= data->GetLength())
				break;
		}
	}
	catch (ReadException&)
	{
		LogWarn("read exception");
	}
}

Md1romView::~Md1romView()
{

}


uint64_t Md1romView::PerformGetEntryPoint() const
{
	return m_entryPoint;
}


BNEndianness Md1romView::PerformGetDefaultEndianness() const
{
	return m_endian;
}


bool Md1romView::PerformIsRelocatable() const
{
	return m_relocatable;
}


size_t Md1romView::PerformGetAddressSize() const
{
	return m_addressSize;
}


bool Md1romView::Init()
{
	return true;
}


Md1romViewType::Md1romViewType(): BinaryViewType("MD1ROM", "MD1ROM")
{
	m_logger = LogRegistry::CreateLogger("BinaryView.Md1romViewType");
}


Ref<BinaryView> Md1romViewType::Create(BinaryView* data)
{
	try
	{
		return new Md1romView(data);
	}
	catch (std::exception& e)
	{
		m_logger->LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}


Ref<BinaryView> Md1romViewType::Parse(BinaryView* data)
{
	try
	{
		return new Md1romView(data, true);
	}
	catch (std::exception& e)
	{
		m_logger->LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}


bool Md1romViewType::IsTypeValidForData(BinaryView* data)
{
	DataBuffer sig = data->ReadBuffer(0, 4);
	if (sig.GetLength() != 4)
		return false;
	if (memcmp(sig.GetData(), "\x88\x16\x88\x58", 4) != 0)
		return false;

	sig = data->ReadBuffer(0x30, 4);
	if (sig.GetLength() != 4)
		return false;
	if (memcmp(sig.GetData(), "\x89\x16\x89\x58", 4) != 0)
		return false;

	return true;
}


Ref<Settings> Md1romViewType::GetLoadSettingsForData(BinaryNinja::BinaryView* data)
{
	return nullptr;
}


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifdef DEMO_VERSION
	bool ElfPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		InitMd1romViewType();
		return true;
	}
}
