// BinaryView for VxWorks Real-Time Operating System (RTOS) images

#include "vxworksview.h"

using namespace BinaryNinja;
using namespace std;

static VxWorksViewType* g_vxWorksViewType = nullptr;

#define NEW_CDM_SIGNATURE_OFFSET 0x0
#define NEW_CDM_SIGNATURE_SIZE 0xb
#define PACKAGED_CDM_SIGNATURE_SIZE 0x3
#define PACKAGED_CDM_SIGNATURE_OFFSET 0x50
static VxWorksImageType IdentifyVxWorksImageType(BinaryReader* reader)
{
    reader->Seek(0);
    uint32_t magic;
    if (!reader->TryRead32(magic))
        return VxWorksUnsupportedImageType;

    if (magic == 0x7c6000a6 || magic == 0x7c631a78)
        return VxWorksStandardImageType;

    uint8_t newCDMSignature[NEW_CDM_SIGNATURE_SIZE];
    reader->Seek(NEW_CDM_SIGNATURE_OFFSET);
    if (!reader->TryRead(newCDMSignature, NEW_CDM_SIGNATURE_SIZE))
        return VxWorksUnsupportedImageType;
    if (memcmp(newCDMSignature, "vxWorks.pkg", NEW_CDM_SIGNATURE_SIZE) == 0)
        return VxWorksCDMNewImageType;

    uint8_t oldCMSSignature[PACKAGED_CDM_SIGNATURE_SIZE];
    reader->Seek(PACKAGED_CDM_SIGNATURE_OFFSET);
    if (!reader->TryRead(oldCMSSignature, PACKAGED_CDM_SIGNATURE_SIZE))
        return VxWorksUnsupportedImageType;
    if (memcmp(oldCMSSignature, "CDM", PACKAGED_CDM_SIGNATURE_SIZE) == 0)
        return VxWorksCDMPackagedImageType;

    return VxWorksUnsupportedImageType;
}


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


bool VxWorksView::DetermineImageBase(BinaryReader *reader)
{
    VxWorksImageType imageType = IdentifyVxWorksImageType(reader);
    switch (imageType)
    {
    case VxWorksStandardImageType:
    {
        uint32_t magic;
        reader->Seek(0);
        if (!reader->TryRead32(magic))
            return 0;

        // TODO: dynamically determine the image base
        switch (magic)
        {
        case 0x7c6000a6: // vx5_ppc_big_endian_0x10000.bin
            m_imageBase = 0x10000;
            return true;
        case 0x7810a0e3: // vx5_arm_little_endian_0x1000.bin
            m_imageBase = 0x1000;
        case 0x7c631a78:
            m_imageBase = 0x400000;
            return true;
        default:
            m_logger->LogError("Unsupported standard VxWorks image magic");
            return false;
        }
    }
    case VxWorksCDMPackagedImageType:
        return false; // TODO - not implemented yet
    case VxWorksCDMNewImageType:
        return false; // TODO - not implemented yet
    default:
        m_logger->LogError("Unsupported VxWorks image type!?");
        return 0;
    }
}


bool VxWorksView::ScanForVxWorks5SymbolTable(BinaryView* parentView, BinaryReader *reader)
{
    uint64_t endDataAddress = m_imageBase + parentView->GetLength();
    VxWorks5SymbolTableEntry entry;
    uint64_t startOffset = parentView->GetLength() - sizeof(entry);
    uint64_t endOffset = 0;
    if (parentView->GetLength() > MAX_SYMBOL_TABLE_REGION_SIZE)
        endOffset = parentView->GetLength() - MAX_SYMBOL_TABLE_REGION_SIZE;
    uint64_t searchPos = startOffset;

    m_logger->LogDebug("Scanning backwards for VxWorks 5 symbol table (0x%016x-0x%016x)...",
        m_imageBase + startOffset, m_imageBase + endOffset);
    while (searchPos > endOffset)
    {
        reader->Seek(searchPos + 4); // Skip the unknown field
        if (!reader->TryRead32(entry.name) || !reader->TryRead32(entry.address) || !reader->TryRead32(entry.flags))
            break;

        if ((entry.name >= m_imageBase && entry.name < endDataAddress) &&
            (entry.address >= m_imageBase && entry.address < endDataAddress))
        {
            // Name and symbol address pointers are within file
            m_symbolTable5.push_back(entry);
            searchPos -= sizeof(entry);
            continue;
        }

        if (m_symbolTable5.size() > MIN_VALID_SYMBOL_ENTRIES)
            break;

        searchPos -= 4;
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
    // TODO scan for VxWorks 6 symbol table
    return ScanForVxWorks5SymbolTable(parentView, reader);
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
            if (symbolName == "usrRoot")
                m_usrRoot = entry.address;
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

    // Sort section information by start address (last first)
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
    if (m_usrRoot)
    {
        // If we found the usrRoot function in the symbol table, use it
        m_entryPoint = m_usrRoot;
        return;
    }

    for (const auto& section : m_sections)
    {
        // No symbol table, set the entry point to the start of .text, likely the _sysInit function
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

        // TODO: identify the platform dynamically
        auto platform = Platform::GetByName("ppc");
        if (!platform)
        {
            m_logger->LogError("Failed to get platform");
            return false;
        }

        m_arch = platform->GetArchitecture();
        SetDefaultPlatform(platform);
        SetDefaultArchitecture(m_arch);

        BinaryReader reader(parentView, m_endianness);
        if (!DetermineImageBase(&reader))
            return false;

        AddAutoSegment(m_imageBase, parentView->GetLength(), 0, parentView->GetLength(),
            SegmentReadable | SegmentWritable | SegmentExecutable);

        if (m_parseOnly)
            return true;

        if (ScanForVxWorksSymbolTable(parentView, &reader))
            ProcessSymbolTable(&reader);
        else
            m_logger->LogWarn("Could not find VxWorks symbol table");

        AddSections(parentView);
        DetermineEntryPoint();
		AddEntryPointForAnalysis(platform, m_entryPoint);
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
    return m_arch->GetAddressSize();
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
	BinaryReader reader(data, BigEndian);
    VxWorksImageType imageType = IdentifyVxWorksImageType(&reader);
    switch (imageType)
    {
    case VxWorksStandardImageType:
        m_logger->LogDebug("VxWorks standard image type detected");
        break;
    case VxWorksCDMPackagedImageType:
        m_logger->LogDebug("VxWorks packaged CDM image type detected");
        break;
    case VxWorksCDMNewImageType:
        m_logger->LogDebug("VxWorks new CDM image type detected");
        break;
    case VxWorksUnsupportedImageType:
        break;
    default:
        break;
    }

    return imageType != VxWorksUnsupportedImageType;
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
	vector<string> overrides = {"loader.platform", "loader.imageBase"};
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