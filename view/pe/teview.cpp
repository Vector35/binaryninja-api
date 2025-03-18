// BinaryView for EFI Terse Executable images
//
// Resources:
//   - https://uefi.org/specs/PI/1.8/V1_TE_Image.html
//   - edk2/BaseTools/Source/C/GenFw/GenFw.c

#include "teview.h"

using namespace BinaryNinja;
using namespace std;

static TEViewType* g_teViewType = nullptr;

void BinaryNinja::InitTEViewType()
{
	static TEViewType type;
	BinaryViewType::Register(&type);
	g_teViewType = &type;
}

void TEView::ReadTEImageHeader(BinaryReader& reader, struct TEImageHeader& header)
{
	header.magic = reader.Read16();
	header.machine = reader.Read16();
	header.numberOfSections = reader.Read8();
	header.subsystem = reader.Read8();
	header.strippedSize = reader.Read16();
	header.addressOfEntrypoint = reader.Read32();
	header.baseOfCode = reader.Read32();
	header.imageBase = reader.Read64();
	header.dataDirectory[0].virtualAddress = reader.Read32();
	header.dataDirectory[0].size = reader.Read32();
	header.dataDirectory[1].virtualAddress = reader.Read32();
	header.dataDirectory[1].size = reader.Read32();

	m_logger->LogDebug(
		"TEImageHeader:\n"
		"\tmagic:                           0x%04x\n"
		"\tmachine:                         0x%04x\n"
		"\tnumberOfSections:                0x%02x\n"
		"\tsubsystem:                       0x%02x\n"
		"\tstrippedSize:                    0x%04x\n"
		"\taddressOfEntrypoint:             0x%08x\n"
		"\tbaseOfCode:                      0x%08x\n"
		"\timageBase:                       0x%016x\n"
		"\tdataDirectory[0].virtualAddress: 0x%08x\n"
		"\tdataDirectory[0].size:           0x%08x\n"
		"\tdataDirectory[1].virtualAddress: 0x%08x\n"
		"\tdataDirectory[1].size:           0x%08x\n",
		header.magic,
		header.machine,
		header.numberOfSections,
		header.subsystem,
		header.strippedSize,
		header.addressOfEntrypoint,
		header.baseOfCode,
		header.imageBase,
		header.dataDirectory[0].virtualAddress,
		header.dataDirectory[0].size,
		header.dataDirectory[1].virtualAddress,
		header.dataDirectory[1].size
	);
}

void TEView::ReadTEImageSectionHeaders(BinaryReader& reader, uint32_t numSections)
{
	for (uint32_t i = 0; i < numSections; i++)
	{
		TEImageSectionHeader section;
		section.name = reader.ReadString(8);
		section.virtualSize = reader.Read32();
		section.virtualAddress = reader.Read32();
		section.sizeOfRawData = reader.Read32();
		section.pointerToRawData = reader.Read32();
		section.pointerToRelocations = reader.Read32();
		section.pointerToLineNumbers = reader.Read32();
		section.numberOfRelocations = reader.Read16();
		section.numberOfLineNumbers = reader.Read16();
		section.characteristics = reader.Read32();

		m_logger->LogDebug(
			"TEImageSectionHeader[%i]\n"
			"\tname: %s\n"
			"\tvirtualSize: %08x\n"
			"\tvirtualAddress: %08x\n"
			"\tsizeOfRawData: %08x\n"
			"\tpointerToRawData: %08x\n"
			"\tpointerToRelocations: %08x\n"
			"\tpointerToLineNumbers: %08x\n"
			"\tnumberOfRelocations: %04x\n"
			"\tnumberOfLineNumbers: %04x\n"
			"\tcharacteristics: %08x\n",
			i,
			section.name.c_str(),
			section.virtualSize,
			section.virtualAddress,
			section.sizeOfRawData,
			section.pointerToRawData,
			section.pointerToRelocations,
			section.pointerToLineNumbers,
			section.numberOfRelocations,
			section.numberOfLineNumbers,
			section.characteristics
		);

		m_sections.push_back(section);
	}
}

void TEView::CreateSections()
{
	BeginBulkAddSegments();
	for (size_t i = 0; i < m_sections.size(); i++)
	{
		auto section = m_sections[i];
		uint32_t flags = 0;
		if (section.characteristics & EFI_IMAGE_SCN_MEM_WRITE)
			flags |= SegmentWritable;
		if (section.characteristics & EFI_IMAGE_SCN_MEM_READ)
			flags |= SegmentReadable;
		if (section.characteristics & EFI_IMAGE_SCN_MEM_EXECUTE)
			flags |= SegmentExecutable;

		AddAutoSegment(
			section.virtualAddress + m_imageBase,
			section.virtualSize,
			section.pointerToRawData - m_headersOffset,
			section.sizeOfRawData,
			flags
		);

		BNSectionSemantics semantics = DefaultSectionSemantics;
		uint32_t pFlags = flags & 0x7;
		if (pFlags == (SegmentReadable | SegmentExecutable))
			semantics = ReadOnlyCodeSectionSemantics;
		else if (pFlags == SegmentReadable)
			semantics = ReadOnlyDataSectionSemantics;
		else if (pFlags == (SegmentReadable | SegmentWritable))
			semantics = ReadWriteDataSectionSemantics;
		AddAutoSection(section.name, section.virtualAddress + m_imageBase, section.virtualSize, semantics);
	}
	EndBulkAddSegments();
}

void TEView::AssignHeaderTypes()
{
	StructureBuilder dataDirectoryBuilder;
	dataDirectoryBuilder.AddMember(Type::IntegerType(4, false), "virtualAddress");
	dataDirectoryBuilder.AddMember(Type::IntegerType(4, false), "size");
	auto dataDirectoryStruct = dataDirectoryBuilder.Finalize();
	auto dataDirectoryType = Type::StructureType(dataDirectoryStruct);
	QualifiedName dataDirectoryName = string("TE_Data_Directory_Entry");
	auto dataDirectoryTypeId = Type::GenerateAutoTypeId("te", dataDirectoryName);
	QualifiedName dataDirectoryTypeName = DefineType(dataDirectoryTypeId, dataDirectoryName, dataDirectoryType);

	StructureBuilder headerBuilder;
	headerBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 2), "signature");
	headerBuilder.AddMember(Type::IntegerType(2, false), "machine");
	headerBuilder.AddMember(Type::IntegerType(1, false), "numberOfSections");
	headerBuilder.AddMember(Type::IntegerType(1, false), "subsystem");
	headerBuilder.AddMember(Type::IntegerType(2, false), "strippedSize");
	headerBuilder.AddMember(Type::IntegerType(4, false), "addressOfEntryPoint");
	headerBuilder.AddMember(Type::IntegerType(4, false), "baseOfCode");
	headerBuilder.AddMember(Type::IntegerType(8, false), "imageBase");
	headerBuilder.AddMember(Type::NamedType(this, dataDirectoryTypeName), "baseRelocationTableEntry");
	headerBuilder.AddMember(Type::NamedType(this, dataDirectoryTypeName), "debugEntry");

	auto headerStruct = headerBuilder.Finalize();
	auto headerType = Type::StructureType(headerStruct);
	QualifiedName headerName = string("TE_Header");
	auto headerTypeId = Type::GenerateAutoTypeId("te", headerName);
	QualifiedName headerTypeName = DefineType(headerTypeId, headerName, headerType);
	DefineDataVariable(m_imageBase + m_headersOffset, Type::NamedType(this, headerTypeName));
	DefineAutoSymbol(new Symbol(DataSymbol, "__te_header", m_imageBase + m_headersOffset, NoBinding));

	StructureBuilder sectionBuilder;
	sectionBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 8), "name");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "virtualSize");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "virtualAddress");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "sizeOfRawData");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "pointerToRawData");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "pointerToRelocations");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "pointerToLineNumbers");
	sectionBuilder.AddMember(Type::IntegerType(2, false), "numberOfRelocations");
	sectionBuilder.AddMember(Type::IntegerType(2, false), "numberOfLineNumbers");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "characteristics");

	auto sectionStruct = sectionBuilder.Finalize();
	auto sectionType = Type::StructureType(sectionStruct);
	QualifiedName sectionName = string("TE_Section_Header");
	auto sectionTypeId = Type::GenerateAutoTypeId("te", sectionName);
	QualifiedName sectionTypeName = DefineType(sectionTypeId, sectionName, sectionType);
	DefineDataVariable(
		m_imageBase + m_headersOffset + EFI_TE_IMAGE_HEADER_SIZE,
		Type::ArrayType(Type::NamedType(this, sectionTypeName), m_sections.size())
	);
	DefineAutoSymbol(new Symbol(DataSymbol, "__section_headers", m_imageBase + m_headersOffset + EFI_TE_IMAGE_HEADER_SIZE, NoBinding));
}

TEView::TEView(BinaryView* bv, bool parseOnly) : BinaryView("TE", bv->GetFile(), bv), m_parseOnly(parseOnly)
{
	CreateLogger("BinaryView");
	m_logger = CreateLogger("BinaryView.TEView");
	m_backedByDatabase = bv->GetFile()->IsBackedByDatabase("TE");
}

bool TEView::Init()
{
	BinaryReader reader(GetParentView(), LittleEndian);
	struct TEImageHeader header;
	Ref<Platform> platform;

	try
	{
		// Read image header and section headers
		ReadTEImageHeader(reader, header);
		ReadTEImageSectionHeaders(reader, header.numberOfSections);
		m_headersOffset = header.strippedSize - EFI_TE_IMAGE_HEADER_SIZE;

		// m_imageBase represents the base of the original PE image (before headers were stripped), not the base of the
		// TE image (bv.start)
		m_imageBase = header.imageBase;

		// Set architecture and platform
		auto settings = GetLoadSettings(GetTypeName());
		if (settings)
		{
			if (settings->Contains("loader.imageBase"))
			{
				uint64_t baseOverride = settings->Get<uint64_t>("loader.imageBase", this);
				// Apply the headers offset adjustment to compute the base of the original PE image
				m_imageBase = baseOverride - m_headersOffset;
			}

			if (settings->Contains("loader.platform"))
				platform = Platform::GetByName(settings->Get<string>("loader.platform", this));
		}

		if (!platform)
		{
			switch (header.machine)
			{
			case IMAGE_FILE_MACHINE_I386:
				platform = Platform::GetByName("efi-x86");
				break;
			case IMAGE_FILE_MACHINE_AMD64:
				platform = Platform::GetByName("efi-x86_64");
				break;
			case IMAGE_FILE_MACHINE_ARM64:
				platform = Platform::GetByName("efi-aarch64");
				break;
			case IMAGE_FILE_MACHINE_ARM:
				platform = Platform::GetByName("efi-armv7");
				break;
			case IMAGE_FILE_MACHINE_THUMB:
				platform = Platform::GetByName("efi-thumb2");
				break;
			default:
				LogError("TE platform '0x%x' is not supported", header.machine);
				if (!m_parseOnly)
					m_logger->LogWarn("Unable to determine architecture. Please open the file with options and select a valid architecture.");
				return false;
			}
		}

		m_arch = platform->GetArchitecture();
		if (!m_arch)
		{
			LogError("Architecture not supported by this version of Binary Ninja");
			return false;
		}

		SetDefaultPlatform(platform);
		SetDefaultArchitecture(m_arch);

		// Create a segment for the header so that it can be viewed and create sections
		uint64_t headerSegmentSize = reader.GetOffset();
		AddAutoSegment(m_imageBase + m_headersOffset, headerSegmentSize, 0, headerSegmentSize, SegmentReadable);
		CreateSections();
		AssignHeaderTypes();

		// Finished for parse only mode
		if (m_parseOnly)
			return true;

		m_entryPoint = m_imageBase + header.addressOfEntrypoint;
		DefineAutoSymbol(new Symbol(FunctionSymbol, "_start", m_entryPoint));
		AddEntryPointForAnalysis(platform, m_entryPoint);
	}
	catch (std::exception& e)
	{
		m_logger->LogError("Failed to parse TE headers: %s\n", e.what());
		return false;
	}

	return true;
}

uint64_t TEView::PerformGetEntryPoint() const
{
	return m_entryPoint;
}

size_t TEView::PerformGetAddressSize() const
{
	return m_arch->GetAddressSize();
}

TEViewType::TEViewType() : BinaryViewType("TE", "TE")
{
	m_logger = LogRegistry::CreateLogger("BinaryView");
}

Ref<BinaryView> TEViewType::Create(BinaryView* bv)
{
	try
	{
		return new TEView(bv);
	}
	catch (std::exception& e)
	{
		m_logger->LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}

Ref<BinaryView> TEViewType::Parse(BinaryView* bv)
{
	try
	{
		return new TEView(bv, true);
	}
	catch (std::exception& e)
	{
		m_logger->LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}

bool TEViewType::IsTypeValidForData(BinaryView* bv)
{
	// Check the VZ signature
	DataBuffer sig = bv->ReadBuffer(0, 2);
	if (sig.GetLength() != 2)
		return false;
	if (memcmp(sig.GetData(), "VZ", 2))
		return false;

	// Check section header names for .text section
	BinaryReader reader(bv, LittleEndian);
	reader.Seek(0x4);
	uint8_t numSections;
	if (!reader.TryRead8(numSections))
		return false;

	for (uint8_t i = 0; i < numSections; i++)
	{
		reader.Seek(EFI_TE_IMAGE_HEADER_SIZE + (i * EFI_TE_SECTION_HEADER_SIZE));
		uint64_t name;
		if (!reader.TryRead64(name))
			return false;

		if (name == 0x747865742e) // .text
			return true;
	}

	return false;
}

Ref<Settings> TEViewType::GetLoadSettingsForData(BinaryView* data)
{
	Ref<BinaryView> viewRef = Parse(data);
	if (!viewRef || !viewRef->Init())
	{
		m_logger->LogWarn("Failed to initialize view of type '%s'. Generating default load settings.", GetName().c_str());
		viewRef = data;
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
