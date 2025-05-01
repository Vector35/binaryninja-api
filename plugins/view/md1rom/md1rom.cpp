#include "md1rom.h"

using namespace std;
using namespace BinaryNinja;

static Md1romViewType* g_md1romViewType = nullptr;


void BinaryNinja::InitMd1romViewType()
{
	static Md1romViewType type;
	BinaryViewType::Register(&type);
	g_md1romViewType = &type;
}


Md1romView::Md1romView(BinaryNinja::BinaryView* data, bool parseOnly): BinaryView("MD1Rom", data->GetFile(), data),
	m_parseOnly(parseOnly)
{
	(void)m_parseOnly;

	CreateLogger("BinaryView");
	m_logger = CreateLogger("BinaryView.MD1RomView");

	BinaryReader reader(data);
	uint64_t offset = 0;
	try
	{
		while (true)
		{
			Md1romSegment seg;
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
			seg.headerStart = offset;
			seg.dataStart = offset + seg.offset;

			if ((seg.magic != MAGIC_1) || (seg.magic2 != MAGIC_2))
				break;

			m_segments.emplace_back(seg);
			m_logger->LogDebug("segment: %s, offset: 0x%x, length: 0x%x, addr: 0x%x, file offset: 0x%llx",
				seg.name.c_str(), seg.offset, seg.length, seg.addr, offset);

			if (seg.name == "md1rom")
			{
				m_mainRomFound = true;
				m_mainRom = seg;
			}
			else if (seg.name == "md1_dbginfo")
			{
				m_dbgInfoFound = true;
				m_dbgInfoSeg = seg;
			}
			else if (seg.name == "md1_mddb")
			{
				m_dbgDbFound = true;
				m_dbgDatabaseSeg = seg;
			}

			offset += (seg.length + seg.offset);
			if (offset % 0x10 != 0)
				offset = offset - offset % 0x10 + 0x10;

			if (offset >= data->GetLength())
				break;
		}
	}
	catch (ReadException&)
	{
		m_logger->LogWarn("read exception");
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
	if (m_mainRomFound)
	{
		uint64_t mainRomBase = MAIN_ROM_BASE;
		Ref<Settings> settings = GetLoadSettings(GetTypeName());
		if (settings && settings->Contains("loader.imageBase"))
			mainRomBase = settings->Get<uint64_t>("loader.imageBase", this);

		AddAutoSegment(mainRomBase + m_mainRom.addr, m_mainRom.length, m_mainRom.dataStart, m_mainRom.length,
			SegmentExecutable | SegmentReadable | SegmentDenyWrite);
		AddAutoSection(m_mainRom.name, mainRomBase + m_mainRom.addr, m_mainRom.length, ReadOnlyCodeSectionSemantics);
		m_entryPoint = mainRomBase + m_mainRom.addr;

		if (settings && settings->Contains("loader.platform")) // handle overrides
		{
			Ref<Platform> platformOverride = Platform::GetByName(settings->Get<string>("loader.platform", this));
			if (platformOverride)
			{
				m_plat = platformOverride;
				m_arch = m_plat->GetArchitecture();
			}
		}
		else
		{
			m_plat = Platform::GetByName("nanomips");
			m_arch = Architecture::GetByName("nanomips");
			if (!m_arch)
			{
				LogWarn("nanoMIPS architecture not found. Code cannot be disassembled. If you are interested in purchasing "
						"the nanoMIPS architecture plugin, please contact us via https://binary.ninja/support/");
			}
		}

		if (m_arch && m_plat)
		{
			SetDefaultArchitecture(m_arch);
			SetDefaultPlatform(m_plat);
		}
	}

	// Finished for parse only mode
	if (m_parseOnly)
	{
		return true;
	}

	if (m_plat)
	{
		AddEntryPointForAnalysis(m_plat, m_entryPoint);
		// _start is defined by the dbginfo, so we use a different name
		DefineAutoSymbol(new Symbol(FunctionSymbol, "_entry_point", m_entryPoint, GlobalBinding));
	}

	// Create the type for the segment header
	StructureBuilder builder;
	builder.AddMember(Type::IntegerType(4, false), "magic");
	builder.AddMember(Type::IntegerType(4, false), "length");
	builder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 0x20), "name");
	builder.AddMember(Type::IntegerType(4, false), "addr");
	builder.AddMember(Type::IntegerType(4, false), "mode");
	builder.AddMember(Type::IntegerType(4, false), "magic2");
	builder.AddMember(Type::IntegerType(4, false), "offset");
	builder.AddMember(Type::IntegerType(4, false), "unk1");
	builder.AddMember(Type::IntegerType(4, false), "unk2");
	builder.AddMember(Type::IntegerType(4, false), "unk3");
	builder.AddMember(Type::IntegerType(4, false), "unk4");
	builder.AddMember(Type::IntegerType(4, false), "unk5");
	builder.AddMember(Type::IntegerType(4, false), "unk6");

	Ref<Structure> headerStruct = builder.Finalize();
	Ref<Type> headerType = Type::StructureType(headerStruct);
	QualifiedName headerName("Md1rom_Header");
	const string headerTypeId = Type::GenerateAutoTypeId("md1rom", headerName);
	QualifiedName md1HeaderName = GetParentView()->DefineType(headerTypeId, headerName, headerType);

	for (const auto& seg: m_segments)
	{
		GetParentView()->DefineDataVariable(seg.headerStart, Type::NamedType(GetParentView(), md1HeaderName));
		GetParentView()->AddAutoSection(seg.name + "_header", seg.headerStart, seg.offset);
		GetParentView()->AddAutoSection(seg.name + "_data", seg.dataStart, seg.length);
	}

	m_symbolQueue = new SymbolQueue();
	ParseDebugInfo();
	// This does not seem to work, see
	// https://github.com/FirmWire/FirmWire/blob/main/firmwire/vendor/mtk/mtkdb/parse_mdb.py#L30
	// ParseDebugDatabase();

	// Process the queued symbols
	m_symbolQueue->Process();
	delete m_symbolQueue;
	m_symbolQueue = nullptr;

	return true;
}


void Md1romView::DefineMd1RomSymbol(BNSymbolType type, const string& name, uint64_t addr,
	BNSymbolBinding binding, Ref<Type> typeObj)
{
	// If name is empty, symbol is not valid
	if (name.size() == 0)
		return;

	auto process = [=]() {
		NameSpace nameSpace = GetInternalNameSpace();
		// If name does not start with alphabetic character or symbol, prepend an underscore
		string rawName = name;
		if (!(((name[0] >= 'A') && (name[0] <= 'Z')) || ((name[0] >= 'a') && (name[0] <= 'z')) || (name[0] == '_')
				|| (name[0] == '?') || (name[0] == '$') || (name[0] == '@') || (name[0] == '.')))
			rawName = "_" + name;

		return std::pair<Ref<Symbol>, Ref<Type>>(
			new Symbol(type, rawName, rawName, rawName, addr, binding, nameSpace), typeObj);
	};

	if (m_symbolQueue)
	{
		m_symbolQueue->Append(process, [this](Symbol* symbol, Type* type) {
			DefineAutoSymbolAndVariableOrFunction(GetDefaultPlatform(), symbol, type);
		});
	}
	else
	{
		auto result = process();
		DefineAutoSymbolAndVariableOrFunction(GetDefaultPlatform(), result.first, result.second);
	}
}


void Md1romView::ParseDebugInfo()
{
	if (!m_dbgInfoFound)
		return;

	DataBuffer data = GetParentView()->ReadBuffer(m_dbgInfoSeg.dataStart, m_dbgInfoSeg.length);
	if (data.GetLength() != m_dbgInfoSeg.length)
		return;

	DataBuffer decompressed;
	if (!data.LzmaDecompress(decompressed))
		return;

	m_logger->LogDebug("The size of decompressed buffer: 0x%zx", decompressed.GetLength());

	Ref<FileMetadata> file = new FileMetadata;
	Ref<BinaryView> view = new BinaryData(file, decompressed);
	BinaryReader reader(view);

	reader.Seek(0x1c);
	auto target = reader.ReadCString();
    auto hardwarePlatform = reader.ReadCString();
	auto molyVersion = reader.ReadCString();
	auto buildTime = reader.ReadCString();

	[[maybe_unused]] auto functionSymbolsOffset = reader.Read32() + 0x10;
	auto fileSymbolsOffset = reader.Read32() + 0x10;

	try
	{
		while (true)
		{
			Md1DebugSymbol symbol;
			symbol.name = reader.ReadCString();
			symbol.start = reader.Read32();
			symbol.end = reader.Read32();
			m_debugSymbols.emplace_back(symbol);
			DefineMd1RomSymbol(FunctionSymbol, symbol.name, symbol.start);
			if (reader.GetOffset() >= fileSymbolsOffset)
				break;
		}
	}
	catch(...)
	{
		m_logger->LogWarn("exception while parsing debug symbols");
	}
	file->Close();
}


void Md1romView::ParseDebugDatabase()
{
//	if (!m_dbgDbFound)
//		return;
//
//	DataBuffer data = GetParentView()->ReadBuffer(m_dbgDatabaseSeg.dataStart, m_dbgDatabaseSeg.length);
//	if (data.GetLength() != m_dbgDatabaseSeg.length)
//		return;
//
//	Ref<FileMetadata> file = new FileMetadata;
//	Ref<BinaryView> view = new BinaryData(file, data);
//	BinaryReader reader(view);
//
//	if (reader.Read32() != 0x44544143)	//CATD
//		return;
//
//	auto unused = reader.Read32();
//	unused = reader.Read32();
//
//	if (reader.Read32() != 0x44414548)	//HEAD
//		return;
//
//	unused = reader.Read32();
//	auto entryCount = reader.Read32();
//	for (size_t i = 0; i < entryCount; i++)
//	{
//		CATDEntryHeader entry;
//		entry.unknown = reader.Read32();
//		entry.offset = reader.Read32();
//		entry.size = reader.Read32();
//		m_catdEntryHeaders.emplace_back(entry);
//	}
//
//	for (const auto& header: m_catdEntryHeaders)
//	{
//		if (header.size < 16)
//			continue;
//
//		reader.Seek(header.offset);
//		if (reader.Read32() != 0x41544144)
//			continue;
//
//		reader.Read32();
//		CATDEntry catdEntry;
//		catdEntry.offset = reader.Read32();
//		catdEntry.size = reader.Read32();
//		if (header.size < 20)
//			catdEntry.uncompressedSize = header.size;
//		else
//			catdEntry.uncompressedSize = reader.Read32();
//
//		m_catdEntries.emplace_back(catdEntry);
//	}
//
//	for (const auto& entry: m_catdEntries)
//	{
//		if (entry.size != entry.uncompressedSize)
//		{
//			reader.Seek(entry.offset);
//			auto props = reader.Read64();
//			auto dictionarySize = reader.Read32();
//			auto lc = props % 9;
//			props = props / 9;
//			auto pb = props / 5;
//			auto lp = props % 5;
//		}
//		else
//		{
//
//		}
//	}
}


Md1romViewType::Md1romViewType(): BinaryViewType("MD1Rom", "MD1Rom")
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
	Ref<BinaryView> viewRef = Parse(data);
	if (!viewRef || !viewRef->Init())
	{
		m_logger->LogWarn("Failed to initialize view of type '%s'. Generating default load settings.", GetName().c_str());
		viewRef = data;
	}

	Ref<Settings> settings = GetDefaultLoadSettingsForData(viewRef);

	// specify default load settings that can be overridden
	vector<string> overrides = {"loader.imageBase", "loader.platform"};
	for (const auto& override : overrides)
	{
		if (settings->Contains(override))
			settings->UpdateProperty(override, "readOnly", false);
	}
	return settings;
}


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifdef DEMO_EDITION
	bool Md1RomPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		InitMd1romViewType();
		return true;
	}
}
