// BinaryView for VxWorks Real-Time Operating System (RTOS) images

#include "vxworksview.h"

using namespace BinaryNinja;
using namespace std;

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


#define LOWEST_TEXT_SYMBOL_ADDRESS_START 0xffffffffffffffff
void VxWorksView::DetermineImageBaseFromSymbols()
{
	uint64_t lowestTextAddress = LOWEST_TEXT_SYMBOL_ADDRESS_START;
	if (m_version == VxWorksVersion5)
	{
		for (const auto& entry : m_symbolTable5)
		{
			uint8_t type = VXWORKS_SYMBOL_ENTRY_TYPE(entry.flags);
			if (type == VxWorks5GlobalTextSymbolType && entry.address < lowestTextAddress)
				lowestTextAddress = entry.address;
		}
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


bool VxWorksView::ScanForVxWorks5SymbolTable(BinaryView* parentView, BinaryReader *reader)
{
	VxWorks5SymbolTableEntry entry;
	uint64_t startOffset = parentView->GetLength() - sizeof(entry);
	uint64_t endOffset = 0;
	if (parentView->GetLength() > MAX_SYMBOL_TABLE_REGION_SIZE)
		endOffset = parentView->GetLength() - MAX_SYMBOL_TABLE_REGION_SIZE;
	uint64_t searchPos = startOffset;

	m_logger->LogDebug("Scanning backwards for VxWorks 5 symbol table (0x%016x-0x%016x) (endianess=%s)...",
		startOffset, endOffset, m_endianness == BigEndian ? "big" : "little");
	uint64_t lastNameAddress = 0;
	while (searchPos > endOffset)
	{
		reader->Seek(searchPos + 4); // Skip the unknown field
		if (!reader->TryRead32(entry.name) || !reader->TryRead32(entry.address) || !reader->TryReadBE32(entry.flags))
			break;

		uint8_t type = VXWORKS_SYMBOL_ENTRY_TYPE(entry.flags);
		auto it = VxWorks5SymbolTypeMap.find((VxWorks5SymbolType)type);
		if (entry.name >= lastNameAddress && entry.address != 0 && it != VxWorks5SymbolTypeMap.end())
		{
			// Name address is greater than the last name address and flags has a valid symbol type
			lastNameAddress = entry.name;
			m_symbolTable5.push_back(entry);
			searchPos -= sizeof(entry);
			continue;
		}

		if (m_symbolTable5.size() > MIN_VALID_SYMBOL_ENTRIES)
			break;

		searchPos -= 4;
		lastNameAddress = 0;
		m_symbolTable5.clear();
	}

	if (m_symbolTable5.size() < MIN_VALID_SYMBOL_ENTRIES)
	{
		m_symbolTable5.clear();
		return false;
	}

	m_version = VxWorksVersion5;
	m_logger->LogDebug("Found %d VxWorks 5 symbol table entries", m_symbolTable5.size());
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

	// TODO scan for VxWorks 6 symbol table
	return false;
}


#define MAX_SYMBOL_NAME_LENGTH 128
void VxWorksView::ProcessSymbolTable(BinaryReader *reader)
{
	std::set<uint64_t> textSymbolAddresses;
	std::set<uint64_t> dataSymbolAddresses;
	std::set<uint64_t> roDataSymbolAddresses;
	std::set<uint64_t> externSymbolAddresses;

	switch (m_version)
	{
	case VxWorksVersion5:
	{
		for (const auto& entry : m_symbolTable5)
		{
			reader->Seek(entry.name - m_imageBase);
			string symbolName = reader->ReadCString(MAX_SYMBOL_NAME_LENGTH);
			uint8_t type = VXWORKS_SYMBOL_ENTRY_TYPE(entry.flags);
			auto it = VxWorks5SymbolTypeMap.find((VxWorks5SymbolType)type);
			if (it == VxWorks5SymbolTypeMap.end())
			{
				m_logger->LogError("Unknown VxWorks 5 symbol type: 0x%02x (%s)", type, symbolName.c_str());
				continue;
			}

			auto symbolType = it->second;
			switch (symbolType)
			{
			case FunctionSymbol:
				textSymbolAddresses.insert(entry.address);
				AddFunctionForAnalysis(m_platform, entry.address);
				break;
			case DataSymbol:
				if (type == VxWorks5GlobalAbsoluteSymbolType)
					roDataSymbolAddresses.insert(entry.address);
				else
					dataSymbolAddresses.insert(entry.address);
				break;
			case ExternalSymbol:
				externSymbolAddresses.insert(entry.address);
				break;
			default:
				break;
			}

			DefineAutoSymbol(new Symbol(symbolType, symbolName, entry.address));
			if (symbolName == "sysInit")
				m_sysInit = entry.address;
		}

		break;
	}
	case VxWorksVersion6:
	{
		m_logger->LogError("VxWorks 6 symbol table not implemented yet");
		break;
	}
	case VxWorksUnknownVersion:
	default:
		// Shouldn't get here - we set the VxWorks version when we find the symbol table
		m_logger->LogError(
			"VxWorks version is unknown, cannot apply symbols."
			"Please report this issue."
		);
		return;
	}

	if (textSymbolAddresses.size() > 1)
	{
		m_sections.push_back({
			{ *textSymbolAddresses.begin(), *textSymbolAddresses.rbegin() },
			".text",
			ReadOnlyCodeSectionSemantics
		});
	}

	if (dataSymbolAddresses.size() > 1)
	{
		m_sections.push_back({
			{ *dataSymbolAddresses.begin(), *dataSymbolAddresses.rbegin() },
			".data",
			ReadWriteDataSectionSemantics
		});
	}

	if (externSymbolAddresses.size() > 1)
	{
		m_sections.push_back({
			{ *externSymbolAddresses.begin(), *externSymbolAddresses.rbegin() },
			".extern",
			ExternalSectionSemantics
		});
	}

	if (roDataSymbolAddresses.size() > 1)
	{
		m_sections.push_back({
			{ *roDataSymbolAddresses.begin(), *roDataSymbolAddresses.rbegin() },
			".rodata",
			ReadOnlyDataSectionSemantics
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