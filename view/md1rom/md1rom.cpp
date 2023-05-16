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
