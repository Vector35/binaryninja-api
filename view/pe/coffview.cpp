#include <algorithm>

#include <cstring>
#include <cctype>
#include <string.h>
#include <inttypes.h>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <type_traits>
#include <utility>
#include "coffview.h"

#define STRING_READ_CHUNK_SIZE 32

#define DEBUG_COFF_VERBOSELY 0

#if DEBUG_COFF_VERBOSELY
#define DEBUG_COFF(s) s
#else
#define DEBUG_COFF(s)
#endif

// Define an Enumeration from an EnumerationBuilder:
// Ref<Enumeration> prefixEnum
// Ref<Type> prefixEnumType
// string prefixEnumName
// string prefixEnumId
// QualifiedName prefixEnumTypeName
#define BUILD_ENUM_TYPE(prefix, name, width) \
			Ref<Enumeration> prefix ## Enum = prefix ## Builder.Finalize(); \
			Ref<Type> prefix ## EnumType = Type::EnumerationType(GetParentView()->GetDefaultArchitecture(), prefix ## Enum, width, false); \
			string prefix ## EnumName = name; \
			string prefix ## EnumId = Type::GenerateAutoTypeId("coff", prefix ## EnumName); \
			QualifiedName prefix ## EnumTypeName = DefineType(prefix ## EnumId, prefix ## EnumName, prefix ## EnumType)
// Add member to an EnumerationBuilder:
#define ADD_ENUM_MEMBER(type, name) type ## Builder.AddMemberWithValue(#name, name)

using namespace BinaryNinja;
using namespace std;

// From LLVM COFF.h:
// https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/COFF.h#L37-L45
static const char BigObjMagic[] = {
    '\xc7', '\xa1', '\xba', '\xd1', '\xee', '\xba', '\xa9', '\x4b',
    '\xaf', '\x20', '\xfa', '\xf6', '\x6a', '\xa4', '\xdc', '\xb8',
};

static const char ClGlObjMagic[] = {
    '\x38', '\xfe', '\xb3', '\x0c', '\xa5', '\xd9', '\xab', '\x4d',
    '\xac', '\x9b', '\xd6', '\xb6', '\x22', '\x26', '\x53', '\xc2',
};

static COFFViewType* g_coffViewType = nullptr;

void BinaryNinja::InitCOFFViewType()
{
	static COFFViewType type;
	BinaryViewType::Register(&type);
	g_coffViewType = &type;
}

COFFView::COFFView(BinaryView* data, bool parseOnly): BinaryView("COFF", data->GetFile(), data), m_parseOnly(parseOnly)
{
	CreateLogger("BinaryView");
	m_logger = CreateLogger("BinaryView.COFFView");
}

bool COFFView::Init()
{
	std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();
	map<string, size_t> usedSectionNames;

	BinaryReader reader(GetParentView(), LittleEndian);
	uint64_t entryPointAddress;
	Ref<Platform> platform;

	Ref<Settings> settings;
	COFFHeader header;
	BigObj_COFFHeader header2;

	memset(&header, 0, sizeof(header));
	memset(&header2, 0, sizeof(header2));
	size_t sectionIndexSize = sizeof(header.sectionCount);
	size_t sizeofCOFFSymbol = sizeof(COFFSymbol16);
	size_t sectionHeadersOffset = sizeof(COFFHeader);
	uint32_t sectionCount = 0;
	bool isCLRBinary = false;
	bool isBigCOFF = false;
	m_is64 = false;
	try
	{
		// Read COFF header
		reader.Seek(0);
		header.machine = reader.Read16();

		if (header.machine == IMAGE_FILE_MACHINE_UNKNOWN)
		{
			uint16_t sig2 = reader.Read16();
			if (sig2 == 0xFFFF)
			{
				header2.sig1 = header.machine;
				header2.sig2 = sig2;
				sectionIndexSize = sizeof(header2.sectionCount);
				sizeofCOFFSymbol = sizeof(COFFSymbol32);
				sectionHeadersOffset = sizeof(BigObj_COFFHeader);
				header2.version = reader.Read16();
				header.machine = header2.machine = reader.Read16();
				header.timestamp = header2.timestamp = reader.Read32();
				reader.Read(&header2.UUID, sizeof(header2.UUID));
				if (memcmp(&header2.UUID, BigObjMagic, sizeof(BigObjMagic)) == 0)
				{
					m_logger->LogDebug("COFF Header UUID is big object");
				}
				else if (memcmp(&header2.UUID, ClGlObjMagic, sizeof(ClGlObjMagic)) == 0)
				{
					m_logger->LogError("COFF: header UUID is CL.exe LTO object, no native code to disassemble.");
					return false;
				}
				else
				{
					m_logger->LogError("COFF: header UUID unknown, probably COFF import library (unsupported).");
					return false;
				}
				header2.unused1 = reader.Read32();
				header2.unused2 = reader.Read32();
				header2.unused3 = reader.Read32();
				header2.unused4 = reader.Read32();
				sectionCount = header2.sectionCount = reader.Read32();
				header.coffSymbolTable = header2.coffSymbolTable = reader.Read32();
				header.coffSymbolCount = header2.coffSymbolCount = reader.Read32();
				m_logger->LogDebug("COFFHeader (big):\n"
						"\tsig1:               0x%04x\n"
						"\tsig2:               0x%04x\n"
						"\tmachine:            0x%04x\n"
						"\tsectionCount:       0x%08x\n"
						"\ttimestamp:          0x%08x\n"
						"\tcoffSymbolTable:    0x%08x\n"
						"\tcoffSymbolCount:    0x%08x\n",
						header2.sig1,
						header2.sig2,
						header2.machine,
						header2.sectionCount,
						header2.timestamp,
						header2.coffSymbolTable,
						header2.coffSymbolCount);
			}
			else
			{
				sectionCount = header.sectionCount = sig2;
			}
		}
		else
		{
			sectionCount = header.sectionCount = reader.Read16();
		}
		if (header2.sig2 != 0xFFFF)
		{
			header.timestamp = reader.Read32();
			header.coffSymbolTable = reader.Read32();
			header.coffSymbolCount = reader.Read32();
			header.optionalHeaderSize = reader.Read16();
			header.characteristics = reader.Read16();
			m_logger->LogDebug("COFFHeader:\n"
					"\tmachine:            0x%04x\n"
					"\tsectionCount:       0x%04x\n"
					"\ttimestamp:          0x%08x\n"
					"\tcoffSymbolTable:    0x%08x\n"
					"\tcoffSymbolCount:    0x%08x\n"
					"\toptionalHeaderSize: 0x%04x\n"
					"\tcharacteristics:    0x%04x %s, %s, %s\n",
					header.machine,
					header.sectionCount,
					header.timestamp,
					header.coffSymbolTable,
					header.coffSymbolCount,
					header.optionalHeaderSize,
					header.characteristics,
					header.characteristics & 1 ? "No Relocations" : "",
					header.characteristics & 2 ? "Executable" : "",
					header.characteristics & 0x2000 ? "Dll" : "Unknown");
		}
		isBigCOFF = sectionIndexSize != sizeof(header.sectionCount);

		// TODO: Optional Header for executable COFF files: https://wiki.osdev.org/COFF#Optional_Header

		// Add the entry point as a function if the architecture is supported
		// set m_arch early so the to make it available for the demangler
		m_arch = g_coffViewType->GetArchitecture(header.machine, LittleEndian);
		if (!m_arch)
		{
			m_logger->LogError("COFF: Invalid or unknown machine type %#" PRIx16, header.machine);
			return false;
		}
		m_logger->LogDebug("COFF: Architecture(%#x): %s", header.machine, m_arch->GetName().c_str());

		m_is64 = m_arch->GetAddressSize() == 8;

		m_imageBase = 0; // 0 for COFF? opt.imageBase;
		settings = GetLoadSettings(GetTypeName());
		if (settings)
		{
			if (settings->Contains("loader.imageBase"))
				m_imageBase = settings->Get<uint64_t>("loader.imageBase", this);

			if (settings->Contains("loader.platform"))
			{
				auto platformName = settings->Get<string>("loader.platform", this);
				platform = Platform::GetByName(platformName);
				if (platform)
				{
					m_arch = platform->GetArchitecture();
					m_logger->LogDebug("COFF: loader.platform override (%#x, arch: %s): %s", header.machine, m_arch->GetName().c_str(), platformName.c_str());
				}
				else
				{
					m_logger->LogError("COFF: Cannot find platform \"%s\" specified in loader.platform override", platformName.c_str());
				}
			}
		}

		Ref<Settings> viewSettings = Settings::Instance();
		m_extractMangledTypes = viewSettings->Get<bool>("analysis.extractTypesFromMangledNames", this);
		m_simplifyTemplates = viewSettings->Get<bool>("analysis.types.templateSimplifier", this);

		// Add extra segment to hold header so that it can be viewed.  This must be first so
		// that real sections take priority.
		if (sectionCount)
		{
			m_sizeOfHeaders = sectionHeadersOffset + sectionCount * sizeof(COFFSectionHeader);
			AddAutoSegment(m_imageBase, m_sizeOfHeaders, 0, m_sizeOfHeaders, SegmentReadable);
		}
		else
		{
			m_logger->LogWarn("COFF header sectionCount is 0, no sections added");
			return false;
		}

		// Since COFF files are not image files, they don't have an entry point. So set the entry point
		// to the beginning of the first executable section.
		m_entryPoint = 0;

		// COFF files are object files, to be relocated by the linker, so are always relocatable.
		m_relocatable = true;

		// Read sections
		reader.Seek(sectionHeadersOffset);
		BinaryReader sectionNameReader(GetParentView(), LittleEndian);
		BeginBulkAddSegments();

		for (uint32_t i = 0; i < sectionCount; i++)
		{
			COFFSection section;
			char name[9];
			memset(name, 0, sizeof(name));
			reader.Read(name, 8);
			string resolvedName = name;
			if (name[0] == '/' && header.coffSymbolTable)
			{
				errno = 0;
				uint32_t offset = strtoul(name+1, nullptr, 10);
				if (errno == 0 && offset > 0)
				{
					BinaryReader stringReader(GetParentView(), LittleEndian);
					uint64_t stringTableBase = header.coffSymbolTable + (header.coffSymbolCount * 18);
					stringReader.Seek(stringTableBase);
					uint32_t stringTableLen = stringReader.Read32();
					if ((stringTableBase + stringTableLen) > GetParentView()->GetEnd())
					{
						m_logger->LogError("Cannot resolve section name \"%s\": String table is invalid length", name);
					}
					else if (stringTableBase + offset < GetParentView()->GetEnd())
					{
						sectionNameReader.Seek(stringTableBase + offset);
						resolvedName = sectionNameReader.ReadCString();
					}
					else
					{
						m_logger->LogError("Cannot resolve section name \"%s\": Offset is past end of string table", name);
					}
				}
			}
			section.name = resolvedName;

			section.virtualSize = reader.Read32();
			section.virtualAddress = reader.Read32();
			section.sizeOfRawData = reader.Read32();
			section.pointerToRawData = reader.Read32();
			section.pointerToRelocs = reader.Read32();
			section.pointerToLineNumbers = reader.Read32();
			section.relocCount = reader.Read16();
			section.lineNumberCount = reader.Read16();
			section.characteristics = reader.Read32();

			if (section.virtualSize == 0)
			{
				section.virtualSize = section.sizeOfRawData;
			}
			if (section.virtualAddress == 0)
			{
				section.virtualAddress = section.pointerToRawData;
			}

			if (i > 0)
			{
				auto previous = m_sections[i-1];
				DEBUG_COFF(m_logger->LogDebug("COFF: previous section (%#" PRIx32 ", %#" PRIx32 ", %#" PRIx32 ") new section: %#" PRIx32 ", %#" PRIx32 ")",
					previous.virtualAddress,
					previous.virtualSize,
					previous.virtualAddress + previous.virtualSize + previous.relocCount * sizeof(COFFRelocation),
					section.virtualAddress,
					section.virtualSize));
				if (section.virtualAddress < previous.virtualAddress + previous.virtualSize + previous.relocCount * sizeof(COFFRelocation))
				{
					section.virtualAddress = previous.virtualAddress + previous.virtualSize + previous.relocCount * sizeof(COFFRelocation);
				}
			}

			uint32_t flags = 0;
			if (section.characteristics & 0x80000000)
				flags |= SegmentWritable;
			if (section.characteristics & 0x40000000)
				flags |= SegmentReadable;
			if (section.characteristics & 0x20000000)
				flags |= SegmentExecutable;
			if (section.characteristics & 0x80)
				flags |= SegmentContainsData;
			if (section.characteristics & 0x40)
				flags |= SegmentContainsData;
			if (section.characteristics & 0x20)
				flags |= SegmentContainsCode;

			uint32_t align_characteristic = (section.characteristics & (0x00F00000));
			DEBUG_COFF(m_logger->LogDebug("COFF: align_characteristic: %#" PRIx32 ", %#" PRIx32 "\n", align_characteristic, align_characteristic >> 20));
			if (align_characteristic != 0)
			{
				uint32_t alignment = 1 << ((align_characteristic >> 20) - 1);
				uint32_t mask = alignment - 1;
				DEBUG_COFF(m_logger->LogDebug("COFF: section alignment: %#" PRIx32 ", mask: %#" PRIx32 "\n", alignment, mask));
				section.virtualAddress += (-section.virtualAddress & mask);
			}

			m_logger->LogDebug("COFF: Section [%d]\n"
				"\tsection.name                  %s\n"\
				"\tsection.virtualSize:          %#" PRIx32 "\n"\
				/* "\tsection.physicalAddress:      %#" PRIx32 "\n" */\
				"\tsection.sizeOfRawData:        %#" PRIx32 "\n"\
				"\tsection.pointerToRawData:     %#" PRIx32 "\n"\
				"\tsection.pointerToRelocs:      %#" PRIx32 "\n"\
				"\tsection.pointerToLineNumbers: %#" PRIx32 "\n"\
				"\tsection.relocCount:           %#" PRIx16 "\n"\
				"\tsection.lineNumberCount:      %#" PRIx16 "\n"\
				"\tsection.characteristics:      %#" PRIx32 "\n"\
				"\tsection.virtualAddress:       %#" PRIx32 "\n",\
				i, section.name.c_str(),
				section.virtualSize,
				// section.physicalAddress,
				section.sizeOfRawData,
				section.pointerToRawData,
				section.pointerToRelocs,
				section.pointerToLineNumbers,
				section.relocCount,
				section.lineNumberCount,
				section.characteristics,
				section.virtualAddress
				);

			m_logger->LogDebug("COFF: Segment: Vaddr: %08" PRIx64 " Vsize: %08" PRIx32 \
					" Offset: %08" PRIx32 " Rawsize: %08" PRIx32 " %c%c%c %s\n",
				section.virtualAddress + m_imageBase,
				section.virtualSize,
				section.pointerToRawData,
				section.sizeOfRawData,
				(flags & SegmentExecutable) > 0 ? 'x':'-',
				(flags & SegmentReadable) > 0 ? 'r':'-',
				(flags & SegmentWritable) > 0 ? 'w':'-',
				section.name.c_str());

			m_sections.push_back(section);
			if (!isCLRBinary && section.name == ".cormeta")
				isCLRBinary = true;

			if (!section.virtualSize)
				continue;

			AddAutoSegment(section.virtualAddress + m_imageBase, section.virtualSize, section.pointerToRawData, section.sizeOfRawData, flags);

			// Since COFF files are not image files, they don't have an entry point. So if the entry point isn't
			// already set and this is an executable section, set the entry point to its beginning.
			if (m_entryPoint == 0 && (flags & SegmentExecutable) != 0)
			{
				m_entryPoint = section.virtualAddress;
			}

			BNSectionSemantics semantics = DefaultSectionSemantics;
			uint32_t pFlags = flags & 0x7;
			if (pFlags == (SegmentReadable | SegmentExecutable))
				semantics = ReadOnlyCodeSectionSemantics;
			else if (pFlags == SegmentReadable)
				semantics = ReadOnlyDataSectionSemantics;
			else if (pFlags == (SegmentReadable | SegmentWritable))
				semantics = ReadWriteDataSectionSemantics;

			// FIXME: (from peview.cpp) For now override semantics for well known section names and warn about the semantic promotion
			static map<string, BNSectionSemantics> promotedSectionSemantics =
			{
				{"text", ReadOnlyCodeSectionSemantics},
				{"code", ReadOnlyCodeSectionSemantics},
				{"rdata", ReadOnlyDataSectionSemantics},
				{"data", ReadWriteDataSectionSemantics},
				{"bss", ReadWriteDataSectionSemantics}
			};
			string shortName = section.name;
			if (shortName.length() && shortName[0] == '.')
				shortName.erase(shortName.begin());
			transform(shortName.begin(), shortName.end(), shortName.begin(), ::tolower);
			if (auto itr = promotedSectionSemantics.find(shortName); (itr != promotedSectionSemantics.end()) && (itr->second != semantics))
			{
				m_logger->LogInfo("COFF: %s section semantics have been promoted to facilitate analysis.", section.name.c_str());
				semantics = itr->second;
			}

			auto emplaced = usedSectionNames.emplace(section.name, 1);
			if (emplaced.second)
			{
				AddAutoSection(section.name, section.virtualAddress + m_imageBase, section.virtualSize, semantics);
			}
			else
			{
				stringstream ss;
				ss << section.name << "_" << ++emplaced.first->second;
				AddAutoSection(ss.str(), section.virtualAddress + m_imageBase, section.virtualSize, semantics);
			}
		}

		EndBulkAddSegments();

		// Apply architecture and platform
		if (!m_arch)
		{
			switch (header.machine)
			{
			case IMAGE_FILE_MACHINE_I386:
				m_logger->LogError("Support for COFF architecture 'x86' is not present");
				break;
			case IMAGE_FILE_MACHINE_ARM:
				m_logger->LogError("Support for COFF architecture 'armv7' is not present");
				break;
			case IMAGE_FILE_MACHINE_ARMNT:
				m_logger->LogError("Support for COFF architecture 'thumb2' is not present");
				break;
			case IMAGE_FILE_MACHINE_AMD64:
				m_logger->LogError("Support for COFF architecture 'x86_64' is not present");
				break;
			case IMAGE_FILE_MACHINE_ARM64:
				m_logger->LogError("Support for COFF architecture 'aarch64' is not present");
				break;
			default:
				m_logger->LogError("COFF architecture '0x%x' is not supported", header.machine);
				break;
			}

			if (!m_parseOnly)
				m_logger->LogWarn("Unable to determine architecture. Please open the file with options and select a valid architecture.");

			return false;
		}

		entryPointAddress = m_entryPoint;
		if (header.machine == IMAGE_FILE_MACHINE_ARMNT)
		{
			// Special case for ARMNT machine type: all code is thumb2
			// but low bit of function symbol addresses are not set, so force the
			// entry point address to have its low bit set,
			// otherwise GetAssociatedPlatformByAddress will say it's armv7
			entryPointAddress |= 1;
			m_logger->LogDebug("COFF: IMAGE_FILE_MACHINE_ARMNT, setting low bit in entry point %#" PRIx64 " to %#" PRIx64 "", m_entryPoint, entryPointAddress);
			m_entryPoint = entryPointAddress;
		}

		Ref<Architecture> entryPointArch = m_arch->GetAssociatedArchitectureByAddress(entryPointAddress);
		entryPointAddress = m_entryPoint;
		SetDefaultArchitecture(entryPointArch);
		GetParentView()->SetDefaultArchitecture(entryPointArch);

		if (!platform)
		{
			platform = g_coffViewType->GetPlatform(IMAGE_SUBSYSTEM_UNKNOWN, m_arch);
			m_logger->LogDebug("COFF: initial platform (%#x, arch: %s): %s", header.machine, m_arch->GetName().c_str(), platform->GetName().c_str());
		}

		platform = platform->GetAssociatedPlatformByAddress(entryPointAddress);
		entryPointAddress = m_entryPoint;
		m_logger->LogDebug("COFF: entry point %#" PRIx64 " associated platform (%#x, arch: %s): %s", entryPointAddress, header.machine, m_arch->GetName().c_str(), platform->GetName().c_str());

		SetDefaultPlatform(platform);
		SetDefaultArchitecture(platform->GetArchitecture());
		m_logger->LogDebug("COFF: final entry point %#" PRIx64 " default (%#x, arch: %s): %s", entryPointAddress, header.machine, platform->GetName().c_str(), GetDefaultPlatform()->GetName().c_str());

		// Finished for parse only mode
		if (m_parseOnly)
			return true;

		// Create various COFF header yypes

		// Create COFF Header Type
		EnumerationBuilder coffHeaderMachineBuilder;
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_UNKNOWN);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_AM33);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_AMD64);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_ARM);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_ARM64);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_ARMNT);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_EBC);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_I386);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_IA64);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_M32R);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_MIPS16);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_MIPSFPU);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_MIPSFPU16);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_POWERPC);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_POWERPCFP);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_R4000);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_RISCV32);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_RISCV64);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_RISCV128);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_SH3);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_SH3DSP);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_SH4);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_SH5);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_THUMB);
		ADD_ENUM_MEMBER(coffHeaderMachine, IMAGE_FILE_MACHINE_WCEMIPSV2);
		BUILD_ENUM_TYPE(coffHeaderMachine, "coff_machine", 2);

		// Ref<Enumeration> coffHeaderMachineEnum = coffHeaderMachineBuilder.Finalize();
		// Ref<Type> coffHeaderMachineEnumType = Type::EnumerationType(GetParentView()->GetDefaultArchitecture(), coffHeaderMachineEnum, 2, false);
		// BUILD_ENUM_TYPE(coffHeaderMachine, "coff_machine");
		// string coffHeaderMachineEnumId = Type::GenerateAutoTypeId("coff", coffHeaderMachineEnumName);
		// QualifiedName coffHeaderMachineEnumTypeName = DefineType(coffHeaderMachineEnumId, coffHeaderMachineEnumName, coffHeaderMachineEnumType);

		EnumerationBuilder coffCharacteristicsBuilder;
		ADD_ENUM_MEMBER(coffCharacteristics, IMAGE_FILE_RELOCS_STRIPPED);
		ADD_ENUM_MEMBER(coffCharacteristics, IMAGE_FILE_EXECUTABLE_IMAGE);
		ADD_ENUM_MEMBER(coffCharacteristics, IMAGE_FILE_LINE_NUMS_STRIPPED);
		ADD_ENUM_MEMBER(coffCharacteristics, IMAGE_FILE_LOCAL_SYMS_STRIPPED);
		ADD_ENUM_MEMBER(coffCharacteristics, IMAGE_FILE_AGGRESIVE_WS_TRIM);
		ADD_ENUM_MEMBER(coffCharacteristics, IMAGE_FILE_LARGE_ADDRESS_AWARE);
		ADD_ENUM_MEMBER(coffCharacteristics, IMAGE_FILE_BYTES_REVERSED_LO);
		ADD_ENUM_MEMBER(coffCharacteristics, IMAGE_FILE_32BIT_MACHINE);
		ADD_ENUM_MEMBER(coffCharacteristics, IMAGE_FILE_DEBUG_STRIPPED);
		ADD_ENUM_MEMBER(coffCharacteristics, IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP);
		ADD_ENUM_MEMBER(coffCharacteristics, IMAGE_FILE_NET_RUN_FROM_SWAP);
		ADD_ENUM_MEMBER(coffCharacteristics, IMAGE_FILE_SYSTEM);
		ADD_ENUM_MEMBER(coffCharacteristics, IMAGE_FILE_DLL);
		ADD_ENUM_MEMBER(coffCharacteristics, IMAGE_FILE_UP_SYSTEM_ONLY);
		ADD_ENUM_MEMBER(coffCharacteristics, IMAGE_FILE_BYTES_REVERSED_HI);

		// Ref<Enumeration> coffCharacteristicsEnum = coffCharacteristicsBuilder.Finalize();
		// Ref<Type> coffCharacteristicsEnumType = Type::EnumerationType(GetParentView()->GetDefaultArchitecture(), coffCharacteristicsEnum, 2, false);
		BUILD_ENUM_TYPE(coffCharacteristics, "coff_characteristics", 2);
		// string coffCharacteristicsEnumId = Type::GenerateAutoTypeId("coff", coffCharacteristicsEnumName);
		// QualifiedName coffCharacteristicsEnumTypeName = DefineType(coffCharacteristicsEnumId, coffCharacteristicsEnumName, coffCharacteristicsEnumType);

		// TODO decorate members with comments once comments work with linear view
		StructureBuilder coffHeaderBuilder;
		coffHeaderBuilder.SetPacked(true);
		if (header2.sig2 == 0xFFFF)
		{
			coffHeaderBuilder.AddMember(Type::IntegerType(2, false), "sig1");
			coffHeaderBuilder.AddMember(Type::IntegerType(2, false), "sig2");
			coffHeaderBuilder.AddMember(Type::IntegerType(2, false), "version");
			coffHeaderBuilder.AddMember(Type::NamedType(this, coffHeaderMachineEnumTypeName), "machine");
			coffHeaderBuilder.AddMember(Type::IntegerType(4, false), "timeDateStamp");
			coffHeaderBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, false), 16), "UUID");
			coffHeaderBuilder.AddMember(Type::IntegerType(4, false), "unused1");
			coffHeaderBuilder.AddMember(Type::IntegerType(4, false), "unused2");
			coffHeaderBuilder.AddMember(Type::IntegerType(4, false), "unused3");
			coffHeaderBuilder.AddMember(Type::IntegerType(4, false), "unused4");
			coffHeaderBuilder.AddMember(Type::IntegerType(4, false), "numberOfSections");
			coffHeaderBuilder.AddMember(Type::IntegerType(4, false), "pointerToSymbolTable");
			coffHeaderBuilder.AddMember(Type::IntegerType(4, false), "numberOfSymbols");
		}
		else
		{
			coffHeaderBuilder.AddMember(Type::NamedType(this, coffHeaderMachineEnumTypeName), "machine");
			coffHeaderBuilder.AddMember(Type::IntegerType(2, false), "numberOfSections");
			coffHeaderBuilder.AddMember(Type::IntegerType(4, false), "timeDateStamp");
			coffHeaderBuilder.AddMember(Type::IntegerType(4, false), "pointerToSymbolTable");
			coffHeaderBuilder.AddMember(Type::IntegerType(4, false), "numberOfSymbols");
			coffHeaderBuilder.AddMember(Type::IntegerType(2, false), "sizeOfOptionalHeader");
			coffHeaderBuilder.AddMember(Type::NamedType(this, coffCharacteristicsEnumTypeName), "characteristics");
		}

		Ref<Structure> coffHeaderStruct = coffHeaderBuilder.Finalize();
		Ref<Type> coffHeaderType = Type::StructureType(coffHeaderStruct);
		QualifiedName coffHeaderName = string("COFF_Header");
		string coffHeaderTypeId = Type::GenerateAutoTypeId("coff", coffHeaderName);
		QualifiedName coffHeaderTypeName = DefineType(coffHeaderTypeId, coffHeaderName, coffHeaderType);
		DefineDataVariable(m_imageBase, Type::NamedType(this, coffHeaderTypeName));
		DefineAutoSymbol(new Symbol(DataSymbol, "__coff_header", m_imageBase, NoBinding));

		EnumerationBuilder coffSectionFlagsBuilder;
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_RESERVED_0001);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_RESERVED_0002);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_RESERVED_0004);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_TYPE_NO_PAD);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_RESERVED_0010);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_CNT_CODE);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_CNT_INITIALIZED_DATA);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_CNT_UNINITIALIZED_DATA);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_LNK_OTHER);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_LNK_INFO);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_RESERVED_0400);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_LNK_REMOVE);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_LNK_COMDAT);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_GPREL);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_MEM_PURGEABLE);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_MEM_16BIT);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_MEM_LOCKED);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_MEM_PRELOAD);
		// TODO fix the bug that causes flags to not be displayed when these are added to the enumeration
		// NOTE: not a bug, it's by design -- the EnumerationData::IsBitFieldEnum() condition isn't satisfied because these members have overlapping bits
		// ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_ALIGN_1BYTES);
		// ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_ALIGN_2BYTES);
		// ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_ALIGN_4BYTES);
		// ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_ALIGN_8BYTES);
		// ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_ALIGN_16BYTES);
		// ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_ALIGN_32BYTES);
		// ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_ALIGN_64BYTES);
		// ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_ALIGN_128BYTES);
		// ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_ALIGN_256BYTES);
		// ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_ALIGN_512BYTES);
		// ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_ALIGN_1024BYTES);
		// ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_ALIGN_2048BYTES);
		// ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_ALIGN_4096BYTES);
		// ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_ALIGN_8192BYTES);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_LNK_NRELOC_OVFL);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_MEM_DISCARDABLE);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_MEM_NOT_CACHED);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_MEM_NOT_PAGED);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_MEM_SHARED);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_MEM_EXECUTE);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_MEM_READ);
		ADD_ENUM_MEMBER(coffSectionFlags, IMAGE_SCN_MEM_WRITE);

		// Ref<Enumeration> coffSectionFlagsEnum = coffSectionFlagsBuilder.Finalize();
		// Ref<Type> coffSectionFlagsEnumType = Type::EnumerationType(GetParentView()->GetDefaultArchitecture(), coffSectionFlagsEnum, 4, false);
		BUILD_ENUM_TYPE(coffSectionFlags, "coff_section_flags", 4);
		// string coffSectionFlagsEnumId = Type::GenerateAutoTypeId("coff", coffSectionFlagsEnumName);
		// QualifiedName coffSectionFlagsEnumTypeName = DefineType(coffSectionFlagsEnumId, coffSectionFlagsEnumName, coffSectionFlagsEnumType);

		if (sectionCount)
		{
			StructureBuilder sectionHeaderBuilder;
			sectionHeaderBuilder.SetPacked(true);
			sectionHeaderBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 8), "name");
			sectionHeaderBuilder.AddMember(Type::IntegerType(4, false), "virtualSize");
			sectionHeaderBuilder.AddMember(Type::IntegerType(4, false), "virtualAddress");
			sectionHeaderBuilder.AddMember(Type::IntegerType(4, false), "sizeOfRawData");
			sectionHeaderBuilder.AddMember(Type::IntegerType(4, false), "pointerToRawData");
			sectionHeaderBuilder.AddMember(Type::IntegerType(4, false), "pointerToRelocations");
			sectionHeaderBuilder.AddMember(Type::IntegerType(4, false), "pointerToLineNumbers");
			sectionHeaderBuilder.AddMember(Type::IntegerType(2, false), "numberOfRelocations");
			sectionHeaderBuilder.AddMember(Type::IntegerType(2, false), "numberOfLineNumbers");
			sectionHeaderBuilder.AddMember(Type::NamedType(this, coffSectionFlagsEnumTypeName), "characteristics");

			Ref<Structure> sectionHeaderStruct = sectionHeaderBuilder.Finalize();
			Ref<Type> sectionHeaderStructType = Type::StructureType(sectionHeaderStruct);
			QualifiedName sectionHeaderName = string("COFF_Section_Header");
			string sectionHeaderTypeId = Type::GenerateAutoTypeId("COFF", sectionHeaderName);
			QualifiedName sectionHeaderTypeName = DefineType(sectionHeaderTypeId, sectionHeaderName, sectionHeaderStructType);

			DefineAutoSymbol(new Symbol(DataSymbol, "__section_headers", m_imageBase + sectionHeadersOffset, NoBinding));

			for (uint32_t i = 0; i < sectionCount; i++)
			{
				auto sectionHeaderOffset = sectionHeadersOffset + i * sizeof(COFFSectionHeader);
				string sectionName = m_sections[i].name;
				DefineDataVariable(m_imageBase + sectionHeaderOffset, Type::NamedType(this, sectionHeaderTypeName));
				DefineAutoSymbol(new Symbol(DataSymbol, "__sec_hdr_" + sectionName, m_imageBase + sectionHeaderOffset, NoBinding));
			}
		}
	}
	catch (std::exception& e)
	{
		m_logger->LogError("Failed to parse COFF headers: %s\n", e.what());
		return false;
	}

	// The offset of the symbol table after adjusting for the alignment of the sections that precede it
	uint64_t symbolTableAdjustedOffset = 0;

	try
	{
		// Process COFF symbol table
		if (header.coffSymbolCount)
		{
			EnumerationBuilder coffSymbolTypeBuilder;
			ADD_ENUM_MEMBER(coffSymbolType, IMAGE_SYM_TYPE_NULL);
			ADD_ENUM_MEMBER(coffSymbolType, IMAGE_SYM_TYPE_VOID);
			ADD_ENUM_MEMBER(coffSymbolType, IMAGE_SYM_TYPE_CHAR);
			ADD_ENUM_MEMBER(coffSymbolType, IMAGE_SYM_TYPE_SHORT);
			ADD_ENUM_MEMBER(coffSymbolType, IMAGE_SYM_TYPE_INT);
			ADD_ENUM_MEMBER(coffSymbolType, IMAGE_SYM_TYPE_LONG);
			ADD_ENUM_MEMBER(coffSymbolType, IMAGE_SYM_TYPE_FLOAT);
			ADD_ENUM_MEMBER(coffSymbolType, IMAGE_SYM_TYPE_DOUBLE);
			ADD_ENUM_MEMBER(coffSymbolType, IMAGE_SYM_TYPE_STRUCT);
			ADD_ENUM_MEMBER(coffSymbolType, IMAGE_SYM_TYPE_UNION);
			ADD_ENUM_MEMBER(coffSymbolType, IMAGE_SYM_TYPE_ENUM);
			ADD_ENUM_MEMBER(coffSymbolType, IMAGE_SYM_TYPE_MOE);
			ADD_ENUM_MEMBER(coffSymbolType, IMAGE_SYM_TYPE_BYTE);
			ADD_ENUM_MEMBER(coffSymbolType, IMAGE_SYM_TYPE_WORD);
			ADD_ENUM_MEMBER(coffSymbolType, IMAGE_SYM_TYPE_UINT);
			ADD_ENUM_MEMBER(coffSymbolType, IMAGE_SYM_TYPE_DWORD);
			ADD_ENUM_MEMBER(coffSymbolType, MS_IMAGE_SYM_TYPE_FUNCTION);
			BUILD_ENUM_TYPE(coffSymbolType, "coff_symbol_type", 2);

			EnumerationBuilder coffSymbolStorageClassBuilder;
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_NULL);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_AUTOMATIC);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_EXTERNAL);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_STATIC);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_REGISTER);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_EXTERNAL_DEF);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_LABEL);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_UNDEFINED_LABEL);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_MEMBER_OF_STRUCT);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_ARGUMENT);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_STRUCT_TAG);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_MEMBER_OF_UNION);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_UNION_TAG);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_TYPE_DEFINITION);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_UNDEFINED_STATIC);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_ENUM_TAG);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_MEMBER_OF_ENUM);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_REGISTER_PARAM);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_BIT_FIELD);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_AUTOARG);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_LASTENT);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_BLOCK);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_FUNCTION);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_END_OF_STRUCT);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_FILE);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_SECTION);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_WEAK_EXTERNAL);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_HIDDEN);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_CLR_TOKEN);
			ADD_ENUM_MEMBER(coffSymbolStorageClass, IMAGE_SYM_CLASS_END_OF_FUNCTION);
			BUILD_ENUM_TYPE(coffSymbolStorageClass, "coff_symbol_storage_class", 1);

			StructureBuilder coffSymbolBuilder;
			coffSymbolBuilder.SetPacked(true);
			StructureBuilder longNameBuilder;
			longNameBuilder.SetPacked(true);
			longNameBuilder.AddMember(Type::IntegerType(4, false), "zeroes");
			longNameBuilder.AddMember(Type::IntegerType(4, false), "offset");
			Ref<Structure> longNameStruct = longNameBuilder.Finalize();
			Ref<Type> longNameStructType = Type::StructureType(longNameStruct);
			StructureBuilder nameUnionBuilder;
			nameUnionBuilder.SetStructureType(UnionStructureType);
			nameUnionBuilder.SetPacked(true);
			nameUnionBuilder.AddMember(longNameStructType, "longName");
			nameUnionBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 8), "shortName");
			Ref<Structure> nameUnion = nameUnionBuilder.Finalize();
			Ref<Type> nameUnionType = Type::StructureType(nameUnion);

			coffSymbolBuilder.AddMember(nameUnionType, "name");
			coffSymbolBuilder.AddMember(Type::IntegerType(4, false), "value");
			coffSymbolBuilder.AddMember(Type::IntegerType(sectionIndexSize, true), "sectionNumber");
			coffSymbolBuilder.AddMember(Type::NamedType(this, coffSymbolTypeEnumTypeName), "type");
			coffSymbolBuilder.AddMember(Type::NamedType(this, coffSymbolStorageClassEnumTypeName), "storageClass");
			coffSymbolBuilder.AddMember(Type::IntegerType(1, false), "numberOfAuxSymbols");

			Ref<Structure> coffSymbolStruct = coffSymbolBuilder.Finalize();
			Ref<Type> coffSymbolStructType = Type::StructureType(coffSymbolStruct);
			QualifiedName coffSymbolName = string("COFF_Symbol");
			string coffSymbolTypeId = Type::GenerateAutoTypeId("COFF", coffSymbolName);
			QualifiedName coffSymbolTypeName = DefineType(coffSymbolTypeId, coffSymbolName, coffSymbolStructType);

			//Auxiliary Format 1: Function Definitions
			StructureBuilder coffAuxFunctionDefinitionBuilder;
			coffAuxFunctionDefinitionBuilder.SetPacked(true);
			coffAuxFunctionDefinitionBuilder.AddMember(Type::IntegerType(4, false), "tagIndex");
			coffAuxFunctionDefinitionBuilder.AddMember(Type::IntegerType(4, false), "totalSize");
			coffAuxFunctionDefinitionBuilder.AddMember(Type::IntegerType(4, false), "pointerToLineNumber");
			coffAuxFunctionDefinitionBuilder.AddMember(Type::IntegerType(4, false), "pointerToNextFunction");
			coffAuxFunctionDefinitionBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, false), 2), "unused");
			Ref<Structure> coffAuxFunctionDefinitionStruct = coffAuxFunctionDefinitionBuilder.Finalize();
			Ref<Type> coffAuxFunctionDefinitionStructType = Type::StructureType(coffAuxFunctionDefinitionStruct);
			QualifiedName coffAuxFunctionDefinitionName = string("COFF_AuxFunctionDefinition");
			string coffAuxFunctionDefinitionTypeId = Type::GenerateAutoTypeId("COFF", coffAuxFunctionDefinitionName);
			QualifiedName coffAuxFunctionDefinitionTypeName = DefineType(coffAuxFunctionDefinitionTypeId, coffAuxFunctionDefinitionName, coffAuxFunctionDefinitionStructType);

			// Auxiliary Format 2: .bf and .ef Symbols
			StructureBuilder coffAux_bf_And_ef_SymbolBuilder;
			coffAux_bf_And_ef_SymbolBuilder.SetPacked(true);
			coffAux_bf_And_ef_SymbolBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, false), 4), "unused0");
			coffAux_bf_And_ef_SymbolBuilder.AddMember(Type::IntegerType(4, false), "lineNumber");
			coffAux_bf_And_ef_SymbolBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, false), 6), "unused6");
			coffAux_bf_And_ef_SymbolBuilder.AddMember(Type::IntegerType(4, false), "pointerToNextFunction");
			coffAux_bf_And_ef_SymbolBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, false), 2), "unused16");
			Ref<Structure> coffAux_bf_And_ef_SymbolStruct = coffAux_bf_And_ef_SymbolBuilder.Finalize();
			Ref<Type> coffAux_bf_And_ef_SymbolStructType = Type::StructureType(coffAux_bf_And_ef_SymbolStruct);
			QualifiedName coffAux_bf_And_ef_SymbolName = string("COFF_Aux_bf_And_ef_Symbol");
			string coffAux_bf_And_ef_SymbolTypeId = Type::GenerateAutoTypeId("COFF", coffAux_bf_And_ef_SymbolName);
			QualifiedName coffAux_bf_And_ef_SymbolTypeName = DefineType(coffAux_bf_And_ef_SymbolTypeId, coffAux_bf_And_ef_SymbolName, coffAux_bf_And_ef_SymbolStructType);

			// Auxiliary Format 3: Weak Externals
			StructureBuilder coffAuxWeakExternalBuilder;
			coffAuxWeakExternalBuilder.SetPacked(true);
			coffAuxWeakExternalBuilder.AddMember(Type::IntegerType(4, false), "tagIndex");
			coffAuxWeakExternalBuilder.AddMember(Type::IntegerType(4, false), "characteristics");
			coffAuxWeakExternalBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, false), 10), "unused");
			Ref<Structure> coffAuxWeakExternalStruct = coffAuxWeakExternalBuilder.Finalize();
			Ref<Type> coffAuxWeakExternalStructType = Type::StructureType(coffAuxWeakExternalStruct);
			QualifiedName coffAuxWeakExternalName = string("COFF_AuxWeakExternal");
			string coffAuxWeakExternalTypeId = Type::GenerateAutoTypeId("COFF", coffAuxWeakExternalName);
			QualifiedName coffAuxWeakExternalTypeName = DefineType(coffAuxWeakExternalTypeId, coffAuxWeakExternalName, coffAuxWeakExternalStructType);

			// Auxiliary Format 4: Files
			StructureBuilder coffAuxFileBuilder;
			coffAuxFileBuilder.SetPacked(true);
			coffAuxFileBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 18), "fileName");
			Ref<Structure> coffAuxFileStruct = coffAuxFileBuilder.Finalize();
			Ref<Type> coffAuxFileStructType = Type::StructureType(coffAuxFileStruct);
			QualifiedName coffAuxFileName = string("COFF_AuxFile");
			string coffAuxFileTypeId = Type::GenerateAutoTypeId("COFF", coffAuxFileName);
			QualifiedName coffAuxFileTypeName = DefineType(coffAuxFileTypeId, coffAuxFileName, coffAuxFileStructType);

			// Auxiliary Format 5: Section Definitions
			StructureBuilder coffAuxSectionDefinitionBuilder;
			coffAuxSectionDefinitionBuilder.SetPacked(true);
			coffAuxSectionDefinitionBuilder.AddMember(Type::IntegerType(4, false), "length");
			coffAuxSectionDefinitionBuilder.AddMember(Type::IntegerType(2, false), "numberOfRelocations");
			coffAuxSectionDefinitionBuilder.AddMember(Type::IntegerType(2, false), "numberOfLineNumbers");
			coffAuxSectionDefinitionBuilder.AddMember(Type::IntegerType(4, false), "checkSum");
			coffAuxSectionDefinitionBuilder.AddMember(Type::IntegerType(2, false), "number");
			coffAuxSectionDefinitionBuilder.AddMember(Type::IntegerType(1, false), "selection");
			if (!isBigCOFF)
				coffAuxSectionDefinitionBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, false), 3), "unused");
			else
			{
				coffAuxSectionDefinitionBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, false), 1), "unused");
				coffAuxSectionDefinitionBuilder.AddMember(Type::IntegerType(2, false), "numberHighPart");
			}
			Ref<Structure> coffAuxSectionDefinitionStruct = coffAuxSectionDefinitionBuilder.Finalize();
			Ref<Type> coffAuxSectionDefinitionStructType = Type::StructureType(coffAuxSectionDefinitionStruct);
			QualifiedName coffAuxSectionDefinitionName = string("COFF_AuxSectionDefinition");
			string coffAuxSectionDefinitionTypeId = Type::GenerateAutoTypeId("COFF", coffAuxSectionDefinitionName);
			QualifiedName coffAuxSectionDefinitionTypeName = DefineType(coffAuxSectionDefinitionTypeId, coffAuxSectionDefinitionName, coffAuxSectionDefinitionStructType);

			// CLR Token Definition
			StructureBuilder coffAuxCLRTokenBuilder;
			coffAuxCLRTokenBuilder.SetPacked(true);
			coffAuxCLRTokenBuilder.AddMember(Type::IntegerType(1, false), "bAuxType");
			coffAuxCLRTokenBuilder.AddMember(Type::IntegerType(1, false), "bReserved");
			coffAuxCLRTokenBuilder.AddMember(Type::IntegerType(4, false), "SymbolTableIndex");
			coffAuxCLRTokenBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 12), "Reserved");
			Ref<Structure> coffAuxCLRTokenStruct = coffAuxCLRTokenBuilder.Finalize();
			Ref<Type> coffAuxCLRTokenStructType = Type::StructureType(coffAuxCLRTokenStruct);
			QualifiedName coffAuxCLRTokenName = string("COFF_AuxCLRToken");
			string coffAuxCLRTokenTypeId = Type::GenerateAutoTypeId("COFF", coffAuxCLRTokenName);
			QualifiedName coffAuxCLRTokenTypeName = DefineType(coffAuxCLRTokenTypeId, coffAuxCLRTokenName, coffAuxCLRTokenStructType);


			// TODO: combine the aux symbol record struct types into a union:
			// StructureBuilder coffAuxSymbolRecordBuilder(UnionStructureType);

			size_t symbolTableSize = header.coffSymbolCount * sizeofCOFFSymbol;
			auto lastSection = m_sections.back();
			symbolTableAdjustedOffset = header.coffSymbolTable - lastSection.pointerToRawData + lastSection.virtualAddress;
			auto coffSymbolTableBase = m_imageBase + symbolTableAdjustedOffset;
			AddAutoSegment(coffSymbolTableBase, symbolTableSize, header.coffSymbolTable, symbolTableSize, SegmentReadable);
			auto emplaced = usedSectionNames.emplace(".symtab", 1);
			if (emplaced.second)
			{
				AddAutoSection(".symtab", coffSymbolTableBase, symbolTableSize, ReadOnlyDataSectionSemantics);
			}
			else
			{
				stringstream ss;
				ss << ".symtab_" << ++emplaced.first->second;
				AddAutoSection(ss.str(), coffSymbolTableBase, symbolTableSize, ReadOnlyDataSectionSemantics);
			}

			DefineDataVariable(coffSymbolTableBase, Type::ArrayType(Type::NamedType(this, coffSymbolName), header.coffSymbolCount));
			DefineAutoSymbol(new Symbol(DataSymbol, "__symtab", coffSymbolTableBase, NoBinding));

			BinaryReader stringReader(GetParentView(), LittleEndian);
			uint64_t stringTableBaseRaw = header.coffSymbolTable + ((uint64_t) header.coffSymbolCount * sizeofCOFFSymbol);

			stringReader.Seek(stringTableBaseRaw);
			uint32_t stringTableSize = stringReader.Read32();
			if ((stringTableBaseRaw + stringTableSize) > GetParentView()->GetEnd())
			{
				throw COFFFormatException("invalid COFF string table size");
			}
			int64_t stringTableBase = stringTableBaseRaw - header.coffSymbolTable + symbolTableAdjustedOffset;
			AddAutoSegment(m_imageBase + stringTableBase, stringTableSize, stringTableBaseRaw, stringTableSize, SegmentReadable);
			emplaced = usedSectionNames.emplace(".strtab", 1);
			if (emplaced.second)
			{
				AddAutoSection(".strtab", m_imageBase + stringTableBase, stringTableSize, ReadOnlyDataSectionSemantics);
			}
			else
			{
				stringstream ss;
				ss << ".strtab_" << ++emplaced.first->second;
				AddAutoSection(ss.str(), m_imageBase + stringTableBase, stringTableSize, ReadOnlyDataSectionSemantics);
			}

			DefineDataVariable(m_imageBase + stringTableBase, Type::IntegerType(4, false));
			DefineAutoSymbol(new Symbol(DataSymbol, "__strtab_size", m_imageBase + stringTableBase, NoBinding));

			DefineAutoSymbol(new Symbol(DataSymbol, "__strtab", m_imageBase + stringTableBase + 4, NoBinding));

			for (size_t i = 0; i < header.coffSymbolCount; i++)
			{
				reader.Seek(header.coffSymbolTable + (i * sizeofCOFFSymbol));
				uint32_t e_zeroes = reader.Read32();
				uint32_t e_offset = reader.Read32();
				uint32_t e_value = reader.Read32();
				uint32_t e_scnum = !isBigCOFF ? (uint32_t)reader.Read16() : reader.Read32();
				uint16_t e_type = reader.Read16();
				uint8_t e_sclass = reader.Read8();
				uint8_t e_numaux = reader.Read8();

				uint64_t virtualAddress = 0;
				switch (e_scnum)
				{
					case IMAGE_SYM_UNDEFINED:
					case (uint16_t)IMAGE_SYM_ABSOLUTE:
					case (uint16_t)IMAGE_SYM_DEBUG:
						break;
					default:
						if (size_t(e_scnum - 1) < m_sections.size())
							virtualAddress = m_sections[size_t(e_scnum - 1)].virtualAddress + e_value;
						break;
				}

				// read symbol name
				string symbolName;
				if (e_zeroes)
				{
					stringReader.Seek(header.coffSymbolTable + (i * sizeofCOFFSymbol));
					symbolName = stringReader.ReadCString(8);
					symbolName = symbolName.substr(0, strlen(symbolName.c_str()));
				}
				else
				{
					stringReader.Seek(stringTableBaseRaw + e_offset);
					symbolName = stringReader.ReadCString();
				}

				BNSymbolBinding binding;
				bool clrFunction = false;
				switch (e_sclass)
				{
					case IMAGE_SYM_CLASS_EXTERNAL:
						binding = GlobalBinding;
						break;
					case IMAGE_SYM_CLASS_STATIC:
						binding = LocalBinding;
						break;
					case IMAGE_SYM_CLASS_CLR_TOKEN:
						clrFunction = true;
						binding = LocalBinding;
						break;
					default:
						binding = NoBinding;
						break;
				}

				uint8_t baseType = (e_type >> 4) & 0x3;
				switch (baseType)
				{
					case IMAGE_SYM_DTYPE_NULL: // no derived type
					{
						if (virtualAddress)
							AddCOFFSymbol(DataSymbol, "", symbolName, virtualAddress, binding);
						break;
					}
					case IMAGE_SYM_DTYPE_POINTER: // pointer to base type
					{
						break;
					}
					case IMAGE_SYM_DTYPE_FUNCTION: // function that returns base type
					{
						if (virtualAddress)
						{
							if (!isCLRBinary)
							{
								auto functionAddress = virtualAddress;
								if (header.machine == IMAGE_FILE_MACHINE_ARMNT)
								{
									// NOTE: for IMAGE_FILE_MACHINE_ARMNT, there are only thumb2 functions,
									// so we force the low bit on for all function symbols
									functionAddress |= 1;
								}
								AddCOFFSymbol(FunctionSymbol, "", symbolName, functionAddress, binding);
							}
							else if (!clrFunction)
							{
								AddCOFFSymbol(DataSymbol, "", symbolName, virtualAddress, binding);
							}
						}
						break;
					}
					case IMAGE_SYM_DTYPE_ARRAY: // array of base type
					{
						break;
					}
					default:
						break;
				}

				auto symbolVirtualAddress = symbolTableAdjustedOffset + (i * sizeofCOFFSymbol);
				DefineDataVariable(m_imageBase + symbolVirtualAddress, Type::NamedType(this, coffSymbolTypeName));
				string symbolStructName = "__symbol(" + symbolName + ")";
				DefineAutoSymbol(new Symbol(DataSymbol, symbolStructName, m_imageBase + symbolVirtualAddress, NoBinding));

				if (e_zeroes == 0)
				{
					DefineDataVariable(m_imageBase + stringTableBase + e_offset, Type::ArrayType(Type::IntegerType(1, true, "char"), symbolName.length() + 1));
					string symbolStringName = "__symbol_name(" + symbolName + ")";
					DefineAutoSymbol(new Symbol(DataSymbol, symbolStringName, m_imageBase + stringTableBase + e_offset, NoBinding));
					DEBUG_COFF(AddUserDataReference(m_imageBase + symbolVirtualAddress, m_imageBase + stringTableBase + e_offset));
				}

				if (e_sclass == IMAGE_SYM_CLASS_STATIC && e_value == 0)
				{
					size_t sectionHeaderOffset = sectionHeadersOffset + (e_scnum - 1) * sizeof(COFFSectionHeader);
					(void)sectionHeaderOffset;
					DEBUG_COFF(AddUserDataReference(m_imageBase + symbolVirtualAddress, m_imageBase + sectionHeaderOffset));
				}
				else if (e_sclass == IMAGE_SYM_CLASS_EXTERNAL && e_value == 0 && e_scnum == IMAGE_SYM_UNDEFINED)
				{
					if (baseType == IMAGE_SYM_DTYPE_FUNCTION)
					{
						AddCOFFSymbol(ExternalSymbol, "", symbolName, symbolVirtualAddress);
					}
					else
					{
						AddCOFFSymbol(ExternalSymbol, "", symbolName, symbolVirtualAddress);
					}
				}

				// Reify auxiliary symbol record entries
				for (size_t j = 0; j < e_numaux; j++)
				{
					auto auxSymbolAddress = symbolVirtualAddress + ((1 + j) * sizeofCOFFSymbol);
					if (e_sclass == IMAGE_SYM_CLASS_EXTERNAL && baseType == IMAGE_SYM_DTYPE_FUNCTION && e_scnum > 0)
					{
						DefineDataVariable(m_imageBase + auxSymbolAddress,
							Type::NamedType(this, coffAuxFunctionDefinitionTypeName));
					}
					else if (e_sclass == IMAGE_SYM_CLASS_FUNCTION)
					{
						DefineDataVariable(m_imageBase + auxSymbolAddress,
							Type::NamedType(this, coffAux_bf_And_ef_SymbolTypeName));
					}
					else if (e_sclass == IMAGE_SYM_CLASS_EXTERNAL && e_scnum == IMAGE_SYM_UNDEFINED && e_value == 0)
					{
						DefineDataVariable(m_imageBase + auxSymbolAddress,
							Type::NamedType(this, coffAuxWeakExternalTypeName));
					}
					else if (e_sclass == IMAGE_SYM_CLASS_FILE && symbolName == ".file")
					{
						DefineDataVariable(m_imageBase + auxSymbolAddress,
							Type::NamedType(this, coffAuxFileTypeName));
					}
					else if (e_sclass == IMAGE_SYM_CLASS_STATIC && usedSectionNames.count(symbolName) > 0)
					{
						DefineDataVariable(m_imageBase + auxSymbolAddress,
							Type::NamedType(this, coffAuxSectionDefinitionTypeName));
					}
					else if (e_sclass == IMAGE_SYM_CLASS_CLR_TOKEN)
					{
						DefineDataVariable(m_imageBase + auxSymbolAddress,
							Type::NamedType(this, coffAuxCLRTokenName));
					}
				}
				i += e_numaux;
			}
		}
	}
	catch (std::exception& e)
	{
		m_logger->LogError("Failed to parse COFF symbol table: %s\n", e.what());
	}

	// From elfview.cpp:
	// Sometimes ELF will specify Thumb entry points w/o the bottom bit set
	// To deal with this we delay adding entry points until after symbols have been resolved
	// and all the functions have been created. This allows us to query the existing functions
	// platform. All in an effort to not create a function with the wrong architecture
	if (entryPointAddress && !isCLRBinary)
	{
		auto entryPoint = entryPointAddress + m_imageBase;
		auto platform = GetDefaultPlatform()->GetAssociatedPlatformByAddress(entryPoint);
		auto func = GetAnalysisFunctionsForAddress(entryPoint);
		if (func.size() == 1)
		{
			if (func[0]->GetPlatform() != platform)
			{
				RemoveAnalysisFunction(func[0], true);
			}
			AddEntryPointForAnalysis(platform, entryPoint);
		}
		else
			AddEntryPointForAnalysis(platform, entryPoint);
	}

	try
	{
		if (sectionCount)
		{
			EnumerationBuilder coffRelType_I386Builder;
			ADD_ENUM_MEMBER(coffRelType_I386, IMAGE_REL_I386_ABSOLUTE);
			ADD_ENUM_MEMBER(coffRelType_I386, IMAGE_REL_I386_DIR16);
			ADD_ENUM_MEMBER(coffRelType_I386, IMAGE_REL_I386_REL16);
			ADD_ENUM_MEMBER(coffRelType_I386, IMAGE_REL_I386_DIR32);
			ADD_ENUM_MEMBER(coffRelType_I386, IMAGE_REL_I386_DIR32NB);
			ADD_ENUM_MEMBER(coffRelType_I386, IMAGE_REL_I386_SEG12);
			ADD_ENUM_MEMBER(coffRelType_I386, IMAGE_REL_I386_SECTION);
			ADD_ENUM_MEMBER(coffRelType_I386, IMAGE_REL_I386_SECREL);
			ADD_ENUM_MEMBER(coffRelType_I386, IMAGE_REL_I386_TOKEN);
			ADD_ENUM_MEMBER(coffRelType_I386, IMAGE_REL_I386_SECREL7);
			ADD_ENUM_MEMBER(coffRelType_I386, IMAGE_REL_I386_REL32);
			BUILD_ENUM_TYPE(coffRelType_I386, "coff_rel_type_i386", 2);

			EnumerationBuilder coffRelType_AMD64Builder;
			ADD_ENUM_MEMBER(coffRelType_AMD64, IMAGE_REL_AMD64_ABSOLUTE);
			ADD_ENUM_MEMBER(coffRelType_AMD64, IMAGE_REL_AMD64_ADDR64);
			ADD_ENUM_MEMBER(coffRelType_AMD64, IMAGE_REL_AMD64_ADDR32);
			ADD_ENUM_MEMBER(coffRelType_AMD64, IMAGE_REL_AMD64_ADDR32NB);
			ADD_ENUM_MEMBER(coffRelType_AMD64, IMAGE_REL_AMD64_REL32);
			ADD_ENUM_MEMBER(coffRelType_AMD64, IMAGE_REL_AMD64_REL32_1);
			ADD_ENUM_MEMBER(coffRelType_AMD64, IMAGE_REL_AMD64_REL32_2);
			ADD_ENUM_MEMBER(coffRelType_AMD64, IMAGE_REL_AMD64_REL32_3);
			ADD_ENUM_MEMBER(coffRelType_AMD64, IMAGE_REL_AMD64_REL32_4);
			ADD_ENUM_MEMBER(coffRelType_AMD64, IMAGE_REL_AMD64_REL32_5);
			ADD_ENUM_MEMBER(coffRelType_AMD64, IMAGE_REL_AMD64_SECTION);
			ADD_ENUM_MEMBER(coffRelType_AMD64, IMAGE_REL_AMD64_SECREL);
			ADD_ENUM_MEMBER(coffRelType_AMD64, IMAGE_REL_AMD64_SECREL7);
			ADD_ENUM_MEMBER(coffRelType_AMD64, IMAGE_REL_AMD64_TOKEN);
			ADD_ENUM_MEMBER(coffRelType_AMD64, IMAGE_REL_AMD64_SREL32);
			ADD_ENUM_MEMBER(coffRelType_AMD64, IMAGE_REL_AMD64_PAIR);
			ADD_ENUM_MEMBER(coffRelType_AMD64, IMAGE_REL_AMD64_SSPAN32);
			BUILD_ENUM_TYPE(coffRelType_AMD64, "coff_rel_type_amd64", 2);

			EnumerationBuilder coffRelType_ARMBuilder;
			ADD_ENUM_MEMBER(coffRelType_ARM, IMAGE_REL_ARM_ABSOLUTE);
			ADD_ENUM_MEMBER(coffRelType_ARM, IMAGE_REL_ARM_ADDR32);
			ADD_ENUM_MEMBER(coffRelType_ARM, IMAGE_REL_ARM_ADDR32NB);
			ADD_ENUM_MEMBER(coffRelType_ARM, IMAGE_REL_ARM_BRANCH24);
			ADD_ENUM_MEMBER(coffRelType_ARM, IMAGE_REL_ARM_BRANCH11);
			ADD_ENUM_MEMBER(coffRelType_ARM, IMAGE_REL_ARM_BLX24);
			ADD_ENUM_MEMBER(coffRelType_ARM, IMAGE_REL_ARM_BLX11);
			ADD_ENUM_MEMBER(coffRelType_ARM, IMAGE_REL_ARM_REL32);
			ADD_ENUM_MEMBER(coffRelType_ARM, IMAGE_REL_ARM_SECTION);
			ADD_ENUM_MEMBER(coffRelType_ARM, IMAGE_REL_ARM_SECREL);
			ADD_ENUM_MEMBER(coffRelType_ARM, IMAGE_REL_ARM_MOV32);
			ADD_ENUM_MEMBER(coffRelType_ARM, IMAGE_REL_THUMB_MOV32);
			ADD_ENUM_MEMBER(coffRelType_ARM, IMAGE_REL_THUMB_BRANCH20);
			ADD_ENUM_MEMBER(coffRelType_ARM, IMAGE_REL_THUMB_UNUSED);
			ADD_ENUM_MEMBER(coffRelType_ARM, IMAGE_REL_THUMB_BRANCH24);
			ADD_ENUM_MEMBER(coffRelType_ARM, IMAGE_REL_THUMB_BLX23);
			ADD_ENUM_MEMBER(coffRelType_ARM, IMAGE_REL_ARM_PAIR);
			BUILD_ENUM_TYPE(coffRelType_ARM, "coff_rel_type_arm", 2);

			EnumerationBuilder coffRelType_ARM64Builder;
			ADD_ENUM_MEMBER(coffRelType_ARM64, IMAGE_REL_ARM64_ABSOLUTE);
			ADD_ENUM_MEMBER(coffRelType_ARM64, IMAGE_REL_ARM64_ADDR32);
			ADD_ENUM_MEMBER(coffRelType_ARM64, IMAGE_REL_ARM64_ADDR32NB);
			ADD_ENUM_MEMBER(coffRelType_ARM64, IMAGE_REL_ARM64_BRANCH26);
			ADD_ENUM_MEMBER(coffRelType_ARM64, IMAGE_REL_ARM64_PAGEBASE_REL21);
			ADD_ENUM_MEMBER(coffRelType_ARM64, IMAGE_REL_ARM64_REL21);
			ADD_ENUM_MEMBER(coffRelType_ARM64, IMAGE_REL_ARM64_PAGEOFFSET_12A);
			ADD_ENUM_MEMBER(coffRelType_ARM64, IMAGE_REL_ARM64_PAGEOFFSET_12L);
			ADD_ENUM_MEMBER(coffRelType_ARM64, IMAGE_REL_ARM64_SECREL);
			ADD_ENUM_MEMBER(coffRelType_ARM64, IMAGE_REL_ARM64_SECREL_LOW12A);
			ADD_ENUM_MEMBER(coffRelType_ARM64, IMAGE_REL_ARM64_SECREL_HIGH12A);
			ADD_ENUM_MEMBER(coffRelType_ARM64, IMAGE_REL_ARM64_SECREL_LOW12L);
			ADD_ENUM_MEMBER(coffRelType_ARM64, IMAGE_REL_ARM64_TOKEN);
			ADD_ENUM_MEMBER(coffRelType_ARM64, IMAGE_REL_ARM64_SECTION);
			ADD_ENUM_MEMBER(coffRelType_ARM64, IMAGE_REL_ARM64_ADDR64);
			ADD_ENUM_MEMBER(coffRelType_ARM64, IMAGE_REL_ARM64_BRANCH19);
			ADD_ENUM_MEMBER(coffRelType_ARM64, IMAGE_REL_ARM64_BRANCH14);
			ADD_ENUM_MEMBER(coffRelType_ARM64, IMAGE_REL_ARM64_REL32);
			BUILD_ENUM_TYPE(coffRelType_ARM64, "coff_rel_type_arm64", 2);

			StructureBuilder coffRelocBuilder;
			coffRelocBuilder.SetPacked(true);
			coffRelocBuilder.AddMember(Type::IntegerType(4, false), "virtualAddress");
			coffRelocBuilder.AddMember(Type::IntegerType(4, false), "symbolTableIndex");
			map<string, QualifiedName> relocationEnumTypes
			{
				{ "x86" , coffRelType_I386EnumTypeName },
				{ "x86_64" , coffRelType_AMD64EnumTypeName },
				{ "armv7" , coffRelType_ARMEnumTypeName },
				{ "armv7eb" , coffRelType_ARMEnumTypeName },		// TODO: relocations probably will not work on armv7 Big Endian
				{ "thumb2" , coffRelType_ARMEnumTypeName },
				{ "thumb2eb" , coffRelType_ARMEnumTypeName },		// TODO: relocations probably will not work on thumb2 Big Endian
				{ "aarch64" , coffRelType_ARM64EnumTypeName },
			};
			if (relocationEnumTypes.find(m_arch->GetName()) != relocationEnumTypes.end())
			{
				coffRelocBuilder.AddMember(Type::NamedType(this, relocationEnumTypes[m_arch->GetName()]), "type");
				DEBUG_COFF(m_logger->LogDebug("COFF: using relocation type '%s' for architecture '%s'", relocationEnumTypes[m_arch->GetName()].GetString().c_str(), m_arch->GetName().c_str()));
			}
			else {
				coffRelocBuilder.AddMember(Type::IntegerType(2, false), "type");
				m_logger->LogDebug("COFF: no relocation type found for architecture '%s', using uint16_t", m_arch->GetName().c_str());
			}

			Ref<Structure> coffRelocStruct = coffRelocBuilder.Finalize();
			Ref<Type> coffRelocStructType = Type::StructureType(coffRelocStruct);
			QualifiedName coffRelocName = string("COFF_Relocation");
			string coffRelocTypeId = Type::GenerateAutoTypeId("COFF", coffRelocName);
			QualifiedName coffRelocTypeName = DefineType(coffRelocTypeId, coffRelocName, coffRelocStructType);

			auto relocHandler = m_arch->GetRelocationHandler("COFF");
			BeginBulkAddSegments();

			for (uint32_t i = 0; i < sectionCount; i++)
			{
				auto section = m_sections[i];
				if (section.relocCount)
				{
					uint32_t relocsFileOffset = section.pointerToRelocs;
					auto relocsVirtualOffset = relocsFileOffset - section.pointerToRawData + section.virtualAddress;
					DEBUG_COFF(m_logger->LogDebug("COFF: section %d reading %d relocations from raw_data: 0x%" PRIx32 " relocs: 0x%" PRIx32 " adjusted offset: %#" PRIx32 " final address: %#" PRIx32,
						i, section.relocCount, section.pointerToRawData, relocsFileOffset, relocsVirtualOffset, m_imageBase + relocsVirtualOffset));
					AddAutoSegment(m_imageBase + relocsVirtualOffset, section.relocCount * sizeof(COFFRelocation), relocsFileOffset, section.relocCount * sizeof(COFFRelocation), SegmentReadable);

					for (auto j = 0; j < section.relocCount; j++)
					{
						uint64_t relocationOffset = relocsVirtualOffset + j * sizeof(COFFRelocation);
						uint64_t relocationFileOffset = relocsFileOffset + j * sizeof(COFFRelocation);

						reader.Seek(relocationFileOffset);
						auto virtualAddress = reader.Read32();
						auto symbolTableIndex = reader.Read32();
						auto relocType = reader.Read16();

						Ref<Type> type = Type::NamedType(this, coffRelocTypeName);
						DefineDataVariable(m_imageBase + relocationOffset, type);

						uint64_t itemAddress = section.virtualAddress + virtualAddress;

						DEBUG_COFF(m_logger->LogDebug("COFF: section %d reloc %d at: 0x%" PRIx32 " va: 0x%x, index: %d, type: 0x%hx, item at: 0x%x",
							i, j, relocationOffset, virtualAddress, symbolTableIndex, relocType, itemAddress));

						DEBUG_COFF(AddUserDataReference(m_imageBase + relocationOffset, m_imageBase + itemAddress));

						uint64_t symbolOffset = symbolTableAdjustedOffset + symbolTableIndex * sizeofCOFFSymbol;

						DEBUG_COFF(AddUserDataReference(m_imageBase + relocationOffset, m_imageBase + symbolOffset));

						const auto symbol = GetSymbolByAddress(m_imageBase + symbolOffset);
						if (!symbol)
						{
							m_logger->LogWarn("COFF: skipping relocation at 0x%" PRIx64 " with invalid symbol address 0x%" PRIx64,
								relocationOffset, m_imageBase + symbolOffset);
							continue;
						}
						string symbolName = symbol->GetRawName();

						auto valueOffset = !isBigCOFF ? offsetof(COFFSymbol16, value) : offsetof(COFFSymbol32, value);
						auto valueFileOffset = header.coffSymbolTable + (symbolTableIndex * sizeofCOFFSymbol) + valueOffset;
						reader.Seek(valueFileOffset);

						COFFSymbol coffSymbol;
						memset(&coffSymbol, 0, sizeof(coffSymbol));
						coffSymbol.value = reader.Read32();
						if (!isBigCOFF)
							coffSymbol.sectionNumber.i16 = reader.Read16();
						else
							coffSymbol.sectionNumber.i32 = reader.Read32();
						coffSymbol.type = reader.Read16();
						coffSymbol.storageClass = reader.Read8();

						DEBUG_COFF(AddUserDataReference(m_imageBase + itemAddress, m_imageBase + symbolOffset));
						DEBUG_COFF(m_logger->LogDebug("COFF: CREATING RELOC SYMBOL REF from 0x%" PRIx64 " to 0x%" PRIx64 " for \"%s\"", m_imageBase + itemAddress, m_imageBase + symbolOffset, symbolName.c_str()));

						DefineAutoSymbol(new Symbol(DataSymbol, "__reloc(" + symbolName + ")", m_imageBase + relocationOffset));

						BNRelocationInfo reloc;
						memset(&reloc, 0, sizeof(reloc));
						reloc.external = false;
						reloc.nativeType = relocType;
						reloc.baseRelative = true;
						reloc.base = m_imageBase;
						reloc.address = itemAddress;
						reloc.size = 4;
						reloc.addend = 0;
						reloc.pcRelative = false;
						reloc.implicitAddend = false;
						int sectionIndex = !isBigCOFF ? coffSymbol.sectionNumber.i16 : coffSymbol.sectionNumber.i32;
						if (sectionIndex > 0)
							reloc.sectionIndex = sectionIndex - 1;
						else
							reloc.sectionIndex = SIZE_MAX;
						DEBUG_COFF(if (sectionIndex <= 0) m_logger->LogDebug("COFF: sectionIndex <= 0 (%d) at 0x%" PRIx64 " for symbol at 0x%" PRIx64, sectionIndex, m_imageBase + relocationOffset,  m_imageBase + symbolOffset));
						if (coffSymbol.storageClass == IMAGE_SYM_CLASS_EXTERNAL || coffSymbol.storageClass == IMAGE_SYM_CLASS_STATIC)
						{
							vector<BNRelocationInfo> relocs;
							relocs.push_back(reloc);
							relocHandler->GetRelocationInfo(this, m_arch, relocs);
							reloc = relocs[0];
							if (sectionIndex > 0)
							{
								uint64_t relocTargetOffset = m_sections[reloc.sectionIndex].virtualAddress + coffSymbol.value;

								DEBUG_COFF(m_logger->LogError("COFF: CREATING RELOC (%d) REF from 0x%" PRIx64 " to 0x%" PRIx64 " for %s", relocType, m_imageBase + itemAddress, m_imageBase + relocTargetOffset, symbolName.c_str()));
								DEBUG_COFF(AddUserDataReference(m_imageBase + itemAddress, m_imageBase + relocTargetOffset));

								DefineRelocation(m_arch, reloc, m_imageBase + relocTargetOffset, m_imageBase + reloc.address);

								DEBUG_COFF(AddUserDataReference(m_imageBase + relocTargetOffset, m_imageBase + itemAddress));
								DEBUG_COFF(m_logger->LogError("COFF: DEFINED RELOCATION for 0x%" PRIx64 ":0x%" PRIx64 " to 0x%" PRIx64 " reloc type %#04x", reloc.base, reloc.address, m_imageBase + relocTargetOffset, reloc.nativeType));
							}
							else if (coffSymbol.storageClass == IMAGE_SYM_CLASS_EXTERNAL)
							{
								DEBUG_COFF(m_logger->LogDebug("COFF: EXTERNAL RELOCATION for 0x%" PRIx64 ":0x%" PRIx64 " reloc type %#04x", reloc.base, reloc.address, reloc.nativeType));
								reloc.external = true;
								Ref<Symbol> targetSymbol;
								reloc.size = m_is64 ? 8 : 4;
								for (const auto& symbol : GetSymbols(m_imageBase + symbolOffset, reloc.size))
								{
									string name = symbol->GetRawName();
									if (name.find("__symbol(") == 0 && name.back() == ')')
									{
										string symbolName = name.substr(strlen("__symbol("));
										symbolName = symbolName.substr(0, symbolName.size() - 1);
										for (const auto& externSymbol : GetSymbolsByName(symbolName))
										{
											auto type = externSymbol->GetType();
											if (type == ExternalSymbol || type == ImportedFunctionSymbol || type == ImportedDataSymbol || type == ImportAddressSymbol)
											{
												targetSymbol = externSymbol;
												DefineRelocation(m_arch, reloc, targetSymbol, m_imageBase + reloc.address);
												DEBUG_COFF(m_logger->LogDebug("COFF: created external relocation at %#" PRIx64 " for %#" PRIx64 ": %s", m_imageBase + relocationOffset, m_imageBase + reloc.address, name.c_str()));
												break;
											}
										}
									}
									if (targetSymbol)
										break;
								}
								if (! targetSymbol)
								{
									// TODO: determine whether this is actually worth logging -- may only be happening for NB (non-based) relocations?
									m_logger->LogError("COFF: no defined external symbol found for relocation at %#" PRIx64 " for symbol %s", m_imageBase + relocationOffset, symbolName.c_str());
								}
							}
						}
					}
				}
			}

			EndBulkAddSegments();
		}
	}
	catch (std::exception& e)
	{
		m_logger->LogError("Failed to parse COFF relocations: %s\n", e.what());
	}

	// Add a symbol for the entry point
	// if (entryPointAddress)
	// 	DefineAutoSymbol(new Symbol(FunctionSymbol, "_start", m_imageBase + entryPointAddress));
	std::chrono::steady_clock::time_point endTime = std::chrono::steady_clock::now();
	double t = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count() / 1000.0;
	m_logger->LogInfo("COFF parsing took %.3f seconds\n", t);

	return true;
}


uint64_t COFFView::RVAToFileOffset(uint64_t offset, bool except)
{
	for (auto& i : m_sections)
	{
		if ((offset >= i.virtualAddress) &&
				(offset < (i.virtualAddress + i.sizeOfRawData)) && (i.virtualSize != 0))
		{
			uint64_t progOfs = offset - i.virtualAddress;
			return i.pointerToRawData + progOfs;
		}
	}

	if (!except)
		return offset;

	throw COFFFormatException("encountered invalid offset");
}


uint32_t COFFView::GetRVACharacteristics(uint64_t offset)
{
	for (auto& i : m_sections)
	{
		if ((offset >= i.virtualAddress) && (offset < (i.virtualAddress + i.virtualSize)) && (i.virtualSize != 0))
			return i.characteristics;
	}
	return 0;
}


string COFFView::ReadString(uint64_t rva)
{
	uint64_t offset = RVAToFileOffset(rva);
	string result;
	char data[STRING_READ_CHUNK_SIZE];
	while (true)
	{
		size_t len = GetParentView()->Read(data, offset, STRING_READ_CHUNK_SIZE);
		if (len == 0)
			break;

		size_t i;
		for (i = 0; i < len; i++)
		{
			if (data[i] == 0)
				break;
		}

		result += string(&data[0], &data[i]);
		if (i < len)
			break;
		offset += len;
	}
	return result;
}


uint16_t COFFView::Read16(uint64_t rva)
{
	uint64_t ofs = RVAToFileOffset(rva);
	BinaryReader reader(GetParentView(), LittleEndian);
	reader.Seek(ofs);
	return reader.Read16();
}


uint32_t COFFView::Read32(uint64_t rva)
{
	uint64_t ofs = RVAToFileOffset(rva);
	BinaryReader reader(GetParentView(), LittleEndian);
	reader.Seek(ofs);
	return reader.Read32();
}


uint64_t COFFView::Read64(uint64_t rva)
{
	uint64_t ofs = RVAToFileOffset(rva);
	BinaryReader reader(GetParentView(), LittleEndian);
	reader.Seek(ofs);
	return reader.Read64();
}


void COFFView::AddCOFFSymbol(BNSymbolType type, const string& dll, const string& name, uint64_t addr,
		BNSymbolBinding binding, uint64_t ordinal, TypeLibrary* lib)
{
	// If name is empty, symbol is not valid
	if (name.size() == 0)
		return;

	// Ensure symbol is within the executable
	NameSpace nameSpace = GetInternalNameSpace();
	if (type == ExternalSymbol)
	{
		nameSpace = GetExternalNameSpace();
	}
	else if (!IsValidOffset(m_imageBase + addr))
	{
		return;
	}
	else if (dll.size())
	{
		nameSpace = NameSpace(dll);
	}

	if (!(type == ExternalSymbol || type == ImportedDataSymbol || type == ImportedFunctionSymbol))
	{
		// Ensure symbol is within the executable
		bool ok = false;
		for (auto& i : m_sections)
		{
			if ((addr >= i.virtualAddress) && (addr < (i.virtualAddress + i.virtualSize)))
			{
				ok = true;
				break;
			}
		}
		if (!ok)
		{
			m_logger->LogDebug("COFF: %s symbol %s at %#" PRIx64 " is not in any section", __func__, name.c_str(), addr);
			return;
		}
	}

	Ref<Type> symbolTypeRef;
	auto address = type == ExternalSymbol ? addr : m_imageBase + addr;
	if (lib && ((type == ImportAddressSymbol) || (type == ImportedDataSymbol)))
	{
		QualifiedName n(name);
		Ref<TypeLibrary> appliedLib = lib;
		symbolTypeRef = ImportTypeLibraryObject(appliedLib, n);
		if (symbolTypeRef && type != ExternalSymbol)
		{
			m_logger->LogDebug("COFF: type library '%s' found hit for '%s'", lib->GetGuid().c_str(), name.c_str());
			RecordImportedObjectLibrary(GetDefaultPlatform(), m_imageBase + addr, appliedLib, n);
		}
	}

	// If name does not start with alphabetic character or symbol, prepend an underscore
	string rawName = name;
	if (!(((name[0] >= 'A') && (name[0] <= 'Z')) ||
				((name[0] >= 'a') && (name[0] <= 'z')) ||
				(name[0] == '_') || (name[0] == '?') || (name[0] == '$') || (name[0] == '@')))
		rawName = "_" + name;

	string shortName = rawName;
	string fullName = rawName;

	if (m_arch && name.size() > 0)
	{
		QualifiedName demangledName;
		Ref<Type> demangledType;
		bool simplify = Settings::Instance()->Get<bool>("analysis.types.templateSimplifier", this);
		if (DemangleGeneric(m_arch, rawName, demangledType, demangledName, this, simplify))
		{
			shortName = demangledName.GetString();
			fullName = shortName;
			if (demangledType)
				fullName += demangledType->GetStringAfterName();
			if (!symbolTypeRef && m_extractMangledTypes && !GetDefaultPlatform()->GetFunctionByName(rawName))
				symbolTypeRef = demangledType;
		}
		else
		{
			m_logger->LogDebug("Failed to demangle: '%s'\n", name.c_str());
		}
	}

	DefineAutoSymbolAndVariableOrFunction(GetDefaultPlatform(),
		new Symbol(type, shortName, fullName, rawName, address, binding, nameSpace, ordinal), symbolTypeRef);
}


uint64_t COFFView::PerformGetEntryPoint() const
{
	return m_imageBase + m_entryPoint;
}


size_t COFFView::PerformGetAddressSize() const
{
	return m_is64 ? 8 : 4;
}


COFFViewType::COFFViewType(): BinaryViewType("COFF", "COFF")
{
	m_logger = LogRegistry::CreateLogger("BinaryView");
}


Ref<BinaryView> COFFViewType::Create(BinaryView* data)
{
	try
	{
		return new COFFView(data);
	}
	catch (std::exception& e)
	{
		m_logger->LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}


Ref<BinaryView> COFFViewType::Parse(BinaryView* data)
{
	try
	{
		return new COFFView(data, true);
	}
	catch (std::exception& e)
	{
		m_logger->LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}

bool COFFViewType::IsValidMachineType(uint16_t machineType)
{
	switch (machineType)
	{
		case IMAGE_FILE_MACHINE_AM33:
		case IMAGE_FILE_MACHINE_AMD64:
		case IMAGE_FILE_MACHINE_ARM:
		case IMAGE_FILE_MACHINE_ARM64:
		case IMAGE_FILE_MACHINE_ARMNT:
		case IMAGE_FILE_MACHINE_EBC:
		case IMAGE_FILE_MACHINE_I386:
		case IMAGE_FILE_MACHINE_IA64:
		case IMAGE_FILE_MACHINE_M32R:
		case IMAGE_FILE_MACHINE_MIPS16:
		case IMAGE_FILE_MACHINE_MIPSFPU:
		case IMAGE_FILE_MACHINE_MIPSFPU16:
		case IMAGE_FILE_MACHINE_POWERPC:
		case IMAGE_FILE_MACHINE_POWERPCFP:
		case IMAGE_FILE_MACHINE_R4000:
		case IMAGE_FILE_MACHINE_RISCV32:
		case IMAGE_FILE_MACHINE_RISCV64:
		case IMAGE_FILE_MACHINE_RISCV128:
		case IMAGE_FILE_MACHINE_SH3:
		case IMAGE_FILE_MACHINE_SH3DSP:
		case IMAGE_FILE_MACHINE_SH4:
		case IMAGE_FILE_MACHINE_SH5:
		case IMAGE_FILE_MACHINE_THUMB:
		case IMAGE_FILE_MACHINE_WCEMIPSV2:
			return true;
		default:
			return false;
	}
}

bool COFFViewType::IsSupportedMachineType(uint16_t machineType)
{
	switch (machineType)
	{
		case IMAGE_FILE_MACHINE_AMD64:
		case IMAGE_FILE_MACHINE_ARM:
		case IMAGE_FILE_MACHINE_ARM64:
		case IMAGE_FILE_MACHINE_ARMNT:
		case IMAGE_FILE_MACHINE_I386:
		case IMAGE_FILE_MACHINE_THUMB:
			return true;
		default:
			return false;
	}
}


bool COFFViewType::IsTypeValidForData(BinaryView* data)
{
	COFFHeader header;
	BinaryReader reader(data, LittleEndian);
	if (!reader.TryRead(&header, sizeof(COFFHeader)))
		return false;
	if (!(COFFViewType::IsSupportedMachineType(header.machine) || (header.machine == IMAGE_FILE_MACHINE_UNKNOWN && COFFViewType::IsSupportedMachineType(((BigObj_COFFHeader*) &header)->machine))))
		return false;
	return true;
}


Ref<Settings> COFFViewType::GetLoadSettingsForData(BinaryView* data)
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
	if (!viewRef->IsRelocatable())
		settings->UpdateProperty("loader.imageBase", "message", "Note: File indicates image is not relocatable.");

	for (const auto& override : overrides)
	{
		if (settings->Contains(override))
			settings->UpdateProperty(override, "readOnly", false);
	}

	// TODO: additional settings

	// register additional settings
	// settings->RegisterSetting("loader.coff.processCfgTable",
	// 		R"({
	// 		"title" : "Process PE Control Flow Guard Table",
	// 		"type" : "boolean",
	// 		"default" : true,
	// 		"description" : "Add function starts sourced from the Control Flow Guard (CFG) table to the core for analysis."
	// 		})");

	// settings->RegisterSetting("loader.coff.processExceptionTable",
	// 		R"({
	// 		"title" : "Process COFF Exception Handling Table",
	// 		"type" : "boolean",
	// 		"default" : true,
	// 		"description" : "Add function starts sourced from the Exception Handling table (.pdata) to the core for analysis."
	// 		})");

	// settings->RegisterSetting("loader.coff.processSehTable",
	// 		R"({
	// 		"title" : "Process COFF Structured Exception Handling Table",
	// 		"type" : "boolean",
	// 		"default" : true,
	// 		"description" : "Add function starts sourced from the Structured Exception Handling (SEH) table to the core for analysis."
	// 		})");


	return settings;
}
