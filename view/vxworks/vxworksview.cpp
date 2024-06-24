// BinaryView for VxWorks Real-Time Operating System (RTOS) images

#include "vxworksview.h"

using namespace BinaryNinja;
using namespace std;

#define MAX_SYMBOL_TABLE_REGION_SIZE 0x2000000
#define VXWORKS5_SYMBOL_ENTRY_SIZE 0x10
#define VXWORKS6_SYMBOL_ENTRY_SIZE 0x14
#define MAX_SYMBOL_NAME_LENGTH 128
#define MIN_VALID_SYMBOL_ENTRIES 1000
#define VXWORKS_SYMBOL_ENTRY_TYPE(flags) (((flags >> 8) & 0xff))
#define LOWEST_TEXT_SYMBOL_ADDRESS_START 0xffffffffffffffff
#define DEFAULT_VXWORKS_BASE_ADDRESS 0x10000
#define MAX_ADDRESSES_ENDIANNESS_CHECK 10

static const std::map<VxWorks5SymbolType, BNSymbolType> VxWorks5SymbolTypeMap = {
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
	{ VxWorks5PowerPCLocalSDASymbolType, DataSymbol },
	{ VxWorks5PowerPCGlobalSDASymbolType, DataSymbol },
	{ VxWorks5PowerPCLocalSDA2SymbolType, DataSymbol },
	{ VxWorks5PowerPCGlobalSDA2SymbolType, DataSymbol },
};

static const std::map<VxWorks6SymbolType, BNSymbolType> VxWorks6SymbolTypeMap = {
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
	{ VxWorks6GlobalSymbols, DataSymbol },
	{ VxWorks6LocalSymbols, DataSymbol },
	{ VxWorks6GlobalSymbols, DataSymbol },
};

static const std::map<std::string, BNSectionSemantics> VxWorksSectionSemanticsMap = {
	{ ".text", ReadOnlyCodeSectionSemantics },
	{ ".data", ReadWriteDataSectionSemantics },
	{ ".rodata", ReadOnlyDataSectionSemantics },
	{ ".extern", ExternalSectionSemantics },
};

static VxWorksViewType* g_vxWorksViewType = nullptr;

void BinaryNinja::InitVxWorksViewType()
{
	static VxWorksViewType type;
	BinaryViewType::Register(&type);
	g_vxWorksViewType = &type;
}


VxWorksView::VxWorksView(BinaryView* data, bool parseOnly): BinaryView("VxWorks", data->GetFile(), data),
	m_parseOnly(parseOnly)
{
	CreateLogger("BinaryView");
	m_logger = CreateLogger("BinaryView.VxWorksView");
}


void VxWorksView::DetermineImageBaseFromSymbols()
{
	uint64_t lowestTextAddress = LOWEST_TEXT_SYMBOL_ADDRESS_START;
	for (const auto& entry : m_symbols)
	{
		uint8_t type = VXWORKS_SYMBOL_ENTRY_TYPE(entry.flags);
		if (m_version == VxWorksVersion5 && type != VxWorks5GlobalTextSymbolType)
			continue;

		if (m_version == VxWorksVersion6 && type != VxWorks6GlobalTextSymbolType)
			continue;

		if (entry.address < lowestTextAddress)
			lowestTextAddress = entry.address;
	}

	if (lowestTextAddress == LOWEST_TEXT_SYMBOL_ADDRESS_START)
	{
		m_logger->LogWarn("Could not determine image base address, using default 0x%08x", DEFAULT_VXWORKS_BASE_ADDRESS);
		m_imageBase = DEFAULT_VXWORKS_BASE_ADDRESS;
		return;
	}

	m_logger->LogDebug("Determined image base address: 0x%016x", lowestTextAddress);
	m_imageBase = lowestTextAddress;
}


// Check least significant byte of the first 10 function symbol addresses to make sure they aren't all the same
bool VxWorksView::FunctionAddressesAreValid(VxWorksVersion version)
{
	std::vector<uint32_t> funcAddresses;
	for (const auto& entry : m_symbols)
	{
		uint8_t type = VXWORKS_SYMBOL_ENTRY_TYPE(entry.flags);
		if (version == VxWorksVersion5 && type != VxWorks5GlobalTextSymbolType)
			continue;

		if (version == VxWorksVersion6 && type != VxWorks6GlobalTextSymbolType)
			continue;

		funcAddresses.push_back(entry.address);
		if (funcAddresses.size() == MAX_ADDRESSES_ENDIANNESS_CHECK)
		{
			uint32_t val = 0;
			for (const auto& addr : funcAddresses)
				val ^= addr;
			return (val & 0xff) != 0;
		}
	}

	// Too few function symbols for check
	return false;
}


bool VxWorksView::ScanForVxWorks6SymbolTable(BinaryView *parentView, BinaryReader *reader)
{
	VxWorksSymbolEntry entry;
	uint64_t startOffset = parentView->GetLength() - VXWORKS6_SYMBOL_ENTRY_SIZE;
	uint64_t endOffset = 0;
	if (parentView->GetLength() > MAX_SYMBOL_TABLE_REGION_SIZE)
		endOffset = parentView->GetLength() - MAX_SYMBOL_TABLE_REGION_SIZE;
	uint64_t searchPos = startOffset;

	m_logger->LogDebug("Scanning backwards for VxWorks 6 symbol table (0x%016x-0x%016x) (endianess=%s)...",
		startOffset, endOffset, m_endianness == BigEndian ? "big" : "little");
	while (searchPos > endOffset)
	{
		reader->Seek(searchPos + 4); // Skip the first unknown field
		if (!reader->TryRead32(entry.name) || !reader->TryRead32(entry.address))
			break;

		reader->Seek(searchPos + 16); // Skip the second unknown field
		if (!reader->TryReadBE32(entry.flags))
			break;

		uint8_t type = VXWORKS_SYMBOL_ENTRY_TYPE(entry.flags);
		auto it = VxWorks6SymbolTypeMap.find((VxWorks6SymbolType)type);
		if (entry.name != 0 &&
			entry.address != 0 &&
			entry.name && it != VxWorks6SymbolTypeMap.end())
		{
			m_symbols.push_back(entry);
			searchPos -= VXWORKS6_SYMBOL_ENTRY_SIZE;
			continue;
		}

		if (m_symbols.size() > MIN_VALID_SYMBOL_ENTRIES && FunctionAddressesAreValid(VxWorksVersion6))
			break;

		searchPos -= 4;
		m_symbols.clear();
	}

	if (m_symbols.size() < MIN_VALID_SYMBOL_ENTRIES)
	{
		m_symbols.clear();
		return false;
	}

	m_version = VxWorksVersion6;
	m_logger->LogDebug("Found %d VxWorks 6 symbol table entries", m_symbols.size());
	return true;
}


bool VxWorksView::ScanForVxWorks5SymbolTable(BinaryView* parentView, BinaryReader *reader)
{
	VxWorksSymbolEntry entry;
	uint64_t startOffset = parentView->GetLength() - VXWORKS5_SYMBOL_ENTRY_SIZE;
	uint64_t endOffset = 0;
	if (parentView->GetLength() > MAX_SYMBOL_TABLE_REGION_SIZE)
		endOffset = parentView->GetLength() - MAX_SYMBOL_TABLE_REGION_SIZE;
	uint64_t searchPos = startOffset;

	m_logger->LogDebug("Scanning backwards for VxWorks 5 symbol table (0x%016x-0x%016x) (endianess=%s)...",
		startOffset, endOffset, m_endianness == BigEndian ? "big" : "little");
	while (searchPos > endOffset)
	{
		reader->Seek(searchPos + 4); // Skip the unknown field
		if (!reader->TryRead32(entry.name) || !reader->TryRead32(entry.address) || !reader->TryReadBE32(entry.flags))
			break;

		uint8_t type = VXWORKS_SYMBOL_ENTRY_TYPE(entry.flags);
		auto it = VxWorks5SymbolTypeMap.find((VxWorks5SymbolType)type);
		if (entry.name != 0 &&
			entry.address != 0 &&
			entry.flags != 0 &&
			it != VxWorks5SymbolTypeMap.end())
		{
			// Name address is greater than the last name address and flags has a valid symbol type
			m_symbols.push_back(entry);
			searchPos -= VXWORKS5_SYMBOL_ENTRY_SIZE;
			continue;
		}

		if (m_symbols.size() > MIN_VALID_SYMBOL_ENTRIES && FunctionAddressesAreValid(VxWorksVersion5))
			break;

		searchPos -= 4;
		m_symbols.clear();
	}

	if (m_symbols.size() < MIN_VALID_SYMBOL_ENTRIES)
	{
		m_symbols.clear();
		return false;
	}

	m_version = VxWorksVersion5;
	m_logger->LogDebug("Found %d VxWorks 5 symbol table entries", m_symbols.size());
	return true;
}


bool VxWorksView::ScanForVxWorksSymbolTable(BinaryView* parentView, BinaryReader *reader)
{
	if (ScanForVxWorks5SymbolTable(parentView, reader))
		return true;

	m_endianness = LittleEndian;
	reader->SetEndianness(m_endianness);
	if (ScanForVxWorks5SymbolTable(parentView, reader))
		return true;

	if (ScanForVxWorks6SymbolTable(parentView, reader))
		return true;
	m_endianness = BigEndian;
	reader->SetEndianness(m_endianness);
	return ScanForVxWorks6SymbolTable(parentView, reader);
}


void VxWorksView::AssignSymbolToSection(std::map<std::string, std::set<uint64_t>>& sections,
	BNSymbolType bnSymbolType, uint8_t vxSymbolType, uint64_t address)
{
	switch (bnSymbolType)
	{
	case FunctionSymbol:
		sections[".text"].insert(address);
		AddFunctionForAnalysis(m_platform, address);
		break;
	case DataSymbol:
		if (m_version == VxWorksVersion5)
		{
			if (vxSymbolType == VxWorks5GlobalAbsoluteSymbolType)
				sections[".rodata"].insert(address);
			else
				sections[".data"].insert(address);
		}

		if (m_version == VxWorksVersion6)
		{
			if (vxSymbolType == VxWorks6GlobalAbsoluteSymbolType)
				sections[".rodata"].insert(address);
			else
				sections[".data"].insert(address);
		}

		break;
	case ExternalSymbol:
		sections[".extern"].insert(address);
		break;
	default:
		m_logger->LogWarn("Unknown symbol type: %d", bnSymbolType);
		break;
	}
}


void VxWorksView::ProcessSymbolTable(BinaryReader *reader)
{
	std::map<std::string, std::set<uint64_t>> sections = {
		{ ".text", {} },
		{ ".data", {} },
		{ ".rodata", {} },
		{ ".extern", {} }
	};

	for (const auto& entry : m_symbols)
	{
		reader->Seek(entry.name - m_imageBase);
		string symbolName = reader->ReadCString(MAX_SYMBOL_NAME_LENGTH);
		uint8_t vxSymbolType = VXWORKS_SYMBOL_ENTRY_TYPE(entry.flags);
		BNSymbolType bnSymbolType;

		switch (m_version)
		{
		case VxWorksVersion5:
		{
			auto it = VxWorks5SymbolTypeMap.find((VxWorks5SymbolType)vxSymbolType);
			if (it == VxWorks5SymbolTypeMap.end())
			{
				m_logger->LogWarn("Unknown VxWorks 5 symbol type: 0x%02x (%s)", vxSymbolType, symbolName.c_str());
				continue;
			}

			bnSymbolType = it->second;
			break;
		}
		case VxWorksVersion6:
		{
			auto it = VxWorks6SymbolTypeMap.find((VxWorks6SymbolType)vxSymbolType);
			if (it == VxWorks6SymbolTypeMap.end())
			{
				m_logger->LogWarn("Unknown VxWorks 6 symbol type: 0x%02x (%s)", vxSymbolType, symbolName.c_str());
				continue;
			}

			bnSymbolType = it->second;
			break;
		}
		default:
			m_logger->LogError("VxWorks version is not set. Please report this issue.");
			return;
		}

		AssignSymbolToSection(sections, bnSymbolType, vxSymbolType, entry.address);
		DefineAutoSymbol(new Symbol(bnSymbolType, symbolName, entry.address));
		if (symbolName == "sysInit")
			m_sysInit = entry.address;
	}

	// Build section info from address ranges of symbols and their types
	for (const auto& section : sections)
	{
		if (section.second.empty())
			continue;

		auto it = VxWorksSectionSemanticsMap.find(section.first);
		if (it == VxWorksSectionSemanticsMap.end())
		{
			m_logger->LogWarn("Unknown section semantics for section: %s. Please report this issue.",
				section.first.c_str());
			continue;
		}

		m_sections.push_back({
			{ *section.second.begin(), *section.second.rbegin() },
			section.first,
			it->second
		});
	}
}


void VxWorksView::AddSections(BinaryView *parentView)
{
	if (m_sections.empty())
	{
		m_logger->LogDebug("No sections found, creating default section");
		AddAutoSection(".text", m_imageBase, parentView->GetLength(), ReadOnlyCodeSectionSemantics);
		return;
	}

	// Sort section information by start address (section w/ highest start address first)
	std::sort(m_sections.begin(), m_sections.end(), [](const VxWorksSectionInfo& a, const VxWorksSectionInfo& b)
	{
		return a.AddressRange.first > b.AddressRange.first;
	});

	uint64_t lastStart = 0;
	bool lastSection = true;
	for (const auto& section : m_sections)
	{
		uint64_t end = lastStart ? lastStart : section.AddressRange.second;
		if (lastSection)
		{
			end = m_imageBase + parentView->GetLength();
			lastSection = false;
		}

		m_logger->LogDebug("Creating section %s at 0x%016x-0x%016x", section.Name.c_str(),
			section.AddressRange.first, end);
		AddAutoSection(section.Name, section.AddressRange.first, end-section.AddressRange.first, section.Semantics);
		lastStart = section.AddressRange.first;
	}
}


void VxWorksView::DetermineEntryPoint()
{
	m_entryPoint = m_imageBase;
	if (m_sysInit)
	{
		// If we found the sysInit function in the symbol table, use it
		m_entryPoint = m_sysInit;
		return;
	}

	for (const auto& section : m_sections)
	{
		// No symbol table, set the entry point to the start of .text, likely the sysInit function
		if (section.Name == ".text")
			m_entryPoint = section.AddressRange.first;
	}
}


bool VxWorksView::Init()
{
	try
	{
		auto parentView = GetParentView();
		if (!parentView)
		{
			m_logger->LogError("Failed to get parent view");
			return false;
		}

		BinaryReader reader(parentView, m_endianness);
		bool isSymTable = ScanForVxWorksSymbolTable(parentView, &reader);
		if (isSymTable)
		{
			DetermineImageBaseFromSymbols();
			m_entryPoint = m_imageBase; // This will get updated later if the sysInit symbol is found
		}
		else
		{
			m_logger->LogWarn("Could not find VxWorks symbol table");
			m_imageBase = DEFAULT_VXWORKS_BASE_ADDRESS;
		}

		AddAutoSegment(m_imageBase, parentView->GetLength(), 0, parentView->GetLength(),
			SegmentReadable | SegmentWritable | SegmentExecutable);

		auto settings = GetLoadSettings(GetTypeName());
		if (!settings || settings->IsEmpty())
		{
			m_endianness = BinaryView::GetDefaultEndianness();
			m_addressSize = BinaryView::GetAddressSize();
			return true;
		}

		auto platformName = settings->Get<string>("loader.platform");
		m_platform = Platform::GetByName(platformName);
		if (!m_platform)
		{
			m_logger->LogError("Failed to get platform");
			return false;
		}

		m_arch = m_platform->GetArchitecture();
		m_addressSize = m_arch->GetAddressSize();
		SetDefaultPlatform(m_platform);
		SetDefaultArchitecture(m_arch);

		if (m_parseOnly)
			return true;

		if (isSymTable)
			ProcessSymbolTable(&reader);
		AddSections(parentView);
		DetermineEntryPoint();
		AddEntryPointForAnalysis(m_platform, m_entryPoint);
		return true;
	}
	catch (std::exception& e)
	{
		m_logger->LogError("Failed to load VxWorks image: %s", e.what());
		return false;
	}

	return true;
}


uint64_t VxWorksView::PerformGetEntryPoint() const
{
	return m_entryPoint;
}


size_t VxWorksView::PerformGetAddressSize() const
{
	return m_addressSize;
}


VxWorksViewType::VxWorksViewType(): BinaryViewType("VxWorks", "VxWorks")
{
	m_logger = LogRegistry::CreateLogger("BinaryView");
}


Ref<BinaryView> VxWorksViewType::Create(BinaryView* data)
{
	try
	{
		return new VxWorksView(data);
	}
	catch (std::exception& e)
	{
		m_logger->LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}


Ref<BinaryView> VxWorksViewType::Parse(BinaryView* data)
{
	try
	{
		return new VxWorksView(data, true);
	}
	catch (std::exception& e)
	{
		m_logger->LogError("%s<BinaryViewType> failed to parse view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}


bool VxWorksViewType::IsTypeValidForData(BinaryView* data)
{
	std::stringstream ss;
	ss << "{"
		"\"pattern\":\"VxWorks\","
		"\"start\":0,"
		"\"end\":" << data->GetLength()-1 << ","
		"\"raw\":false,"
		"\"ignoreCase\":false,"
		"\"overlap\":false,"
		"\"align\":1"
	"}";

	bool isValid = false;;
	auto StringSearchCallback = [&isValid](size_t index, const DataBuffer& dataBuffer) -> bool
	{
		isValid = true;
		return true;
	};

	if (!data->Search(string(ss.str()), StringSearchCallback))
		m_logger->LogWarn("Error while searching for VxWorks signatures in raw view");

	return isValid;
}


Ref<Settings> VxWorksViewType::GetLoadSettingsForData(BinaryView *data)
{
	Ref<BinaryView> viewRef = Parse(data);
	if (!viewRef || !viewRef->Init())
	{
		m_logger->LogError("View type '%s' could not be created", GetName().c_str());
		return nullptr;
	}

	// specify default load settings that can be overridden
	Ref<Settings> settings = GetDefaultLoadSettingsForData(viewRef);
	vector<string> overrides = {"loader.platform", "loader.imageBase", "loader.entryPointOffset"};
	for (const auto& override : overrides)
	{
		if (settings->Contains(override))
			settings->UpdateProperty(override, "readOnly", false);
	}

	if (settings->Contains("loader.entryPointOffset"))
		settings->UpdateProperty("loader.entryPointOffset", "default", viewRef->GetEntryPoint());

	return settings;
}


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifdef DEMO_VERSION
	bool VxWorksPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		InitVxWorksViewType();
		return true;
	}
}