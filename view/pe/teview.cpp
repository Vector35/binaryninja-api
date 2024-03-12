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
}

void TEView::AssignHeaderTypes()
{
	StructureBuilder dataDirectoryBuilder;
	dataDirectoryBuilder.AddMember(Type::IntegerType(4, false), "VirtualAddress");
	dataDirectoryBuilder.AddMember(Type::IntegerType(4, false), "Size");
	auto dataDirectoryStruct = dataDirectoryBuilder.Finalize();
	auto dataDirectoryType = Type::StructureType(dataDirectoryStruct);

	StructureBuilder headerBuilder;
	headerBuilder.AddMember(Type::IntegerType(2, false), "Signature");
	headerBuilder.AddMember(Type::IntegerType(2, false), "Machine");
	headerBuilder.AddMember(Type::IntegerType(1, false), "NumberOfSections");
	headerBuilder.AddMember(Type::IntegerType(1, false), "Subsystem");
	headerBuilder.AddMember(Type::IntegerType(2, false), "StrippedSize");
	headerBuilder.AddMember(Type::IntegerType(4, false), "AddressOfEntryPoint");
	headerBuilder.AddMember(Type::IntegerType(4, false), "BaseOfCode");
	headerBuilder.AddMember(Type::IntegerType(8, false), "ImageBase");
	headerBuilder.AddMember(Type::ArrayType(dataDirectoryType, 2), "DataDirectory");

	auto headerStruct = headerBuilder.Finalize();
	auto headerType = Type::StructureType(headerStruct);
	QualifiedName headerName = string("TE_Header");
	auto headerTypeId = Type::GenerateAutoTypeId("te", headerName);
	QualifiedName headerTypeName = DefineType(headerTypeId, headerName, headerType);
	DefineDataVariable(m_imageBase + m_headersOffset, Type::NamedType(this, headerTypeName));

	StructureBuilder sectionBuilder;
	sectionBuilder.AddMember(Type::IntegerType(8, false), "Name");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "VirtualSize");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "VirtualAddress");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "SizeOfRawData");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "PointerToRawData");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "PointerToRelocations");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "PointerToLinenumbers");
	sectionBuilder.AddMember(Type::IntegerType(2, false), "NumberOfRelocations");
	sectionBuilder.AddMember(Type::IntegerType(2, false), "NumberOfLinenumbers");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "Characteristics");
	auto sectionStruct = sectionBuilder.Finalize();
	auto sectionType = Type::StructureType(sectionStruct);
	for (size_t i = 0; i < m_sections.size(); i++)
	{
		QualifiedName sectionName = string("TE_Section_Header_") + to_string(i);
		auto sectionTypeId = Type::GenerateAutoTypeId("te", sectionName);
		QualifiedName sectionTypeName = DefineType(sectionTypeId, sectionName, sectionType);
		DefineDataVariable(
			m_imageBase + m_headersOffset + EFI_TE_IMAGE_HEADER_SIZE + (EFI_TE_SECTION_HEADER_SIZE * i),
			Type::NamedType(this, sectionTypeName)
		);
	}
}

TEView::TEView(BinaryView* bv, bool parseOnly) : BinaryView("TE", bv->GetFile(), bv), m_parseOnly(parseOnly)
{
	CreateLogger("BinaryView");
	m_logger = CreateLogger("BinaryView.TEView");
	m_backedByDatabase = bv->GetFile()->IsBackedByDatabase("TE");
}

void TEView::HandleUserOverrides()
{
	auto settings = GetLoadSettings(GetTypeName());
	if (!settings)
		return;

	if (settings->Contains("loader.imageBase"))
		m_imageBase = settings->Get<uint64_t>("loader.imageBase", this);

	if (settings->Contains("loader.architecture"))
		m_arch = Architecture::GetByName(settings->Get<string>("loader.architecture", this));
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

		// Set architecture and platform
		HandleUserOverrides();
		if (m_arch)
		{
			auto archName = m_arch->GetName();
			if (archName == "x86")
				platform = Platform::GetByName("efi-x86");
			if (archName == "x86_64")
				platform = Platform::GetByName("efi-x86_64");
			if (archName == "aarch64")
				platform = Platform::GetByName("efi-aarch64");
			if (!platform)
			{
				m_logger->LogError("TE architecture '%s' is not supported", archName.c_str());
				return false;
			}
		}
		else
		{
			m_imageBase = header.imageBase;
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
			default:
				LogError("TE architecture '0x%x' is not supported", header.machine);
				return false;
			}

			if (!platform)
			{
				// Should never occur as long as the platforms exist
				m_logger->LogError("Failed to set platform for TE file");
				return false;
			}

			m_arch = platform->GetArchitecture();
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
	return m_imageBase + m_entryPoint;
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

Ref<Settings> TEViewType::GetLoadSettingsForData(BinaryView *bv)
{
	Ref<BinaryView> viewRef = Parse(bv);
	if (!viewRef || !viewRef->Init())
	{
		m_logger->LogError("View type '%s' could not be created", GetName().c_str());
		return nullptr;
	}

	// specify default load settings that can be overridden
	Ref<Settings> settings = GetDefaultLoadSettingsForData(viewRef);
	vector<string> overrides = {"loader.architecture", "loader.imageBase"};
	for (const auto& override : overrides)
	{
		if (settings->Contains(override))
			settings->UpdateProperty(override, "readOnly", false);
	}

	return settings;
}
