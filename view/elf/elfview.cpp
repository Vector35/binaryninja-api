#include <string.h>
#ifndef _MSC_VER
#include <cxxabi.h>
#endif
#include <inttypes.h>
#include "elfview.h"

#define STRING_READ_CHUNK_SIZE 32

using namespace BinaryNinja;
using namespace std;


static ElfViewType* g_elfViewType = nullptr;


void BinaryNinja::InitElfViewType()
{
	static ElfViewType type;
	BinaryViewType::Register(&type);
	g_elfViewType = &type;

	Ref<Settings> settings = Settings::Instance();
	settings->RegisterSetting("files.elf.maxSectionHeaderCount",
		R"({
		"title" : "Maximum ELF Section Header Count",
		"type" : "number",
		"default" : 100,
		"minValue" : 0,
		"maxValue" : 65536,
		"description" : "Maximum number of entries to include in section header array",
		"ignore" : ["SettingsProjectScope"]
		})");

	settings->RegisterSetting("files.elf.detectARMBE8Binary",
		R"({
		"title" : "Enable ARM BE8 binary detection",
		"type" : "boolean",
		"default" : true,
		"description" : "Enable ARM BE8 binary detection for mixed little/big endianness for code/data",
		"ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
		})");
}


ElfView::ElfView(BinaryView* data, bool parseOnly): BinaryView("ELF", data->GetFile(), data), m_parseOnly(parseOnly)
{
	Elf64Header header;
	string errorMsg;
	BNEndianness endian;
	if (!g_elfViewType->ParseHeaders(data, m_ident, m_commonHeader, header, &m_arch, &m_plat, errorMsg, endian))
		throw ElfFormatException(errorMsg);

	CreateLogger("BinaryView");
	m_logger = CreateLogger("BinaryView.ElfView");
	m_elf32 = m_ident.fileClass == 1;
	m_addressSize = (m_ident.fileClass == 1) ? 4 : 8;
	m_endian = endian;
	m_relocatable = m_commonHeader.type == ET_DYN || m_commonHeader.type == ET_REL;
	m_objectFile = m_commonHeader.type == ET_REL;
	m_backedByDatabase = data->GetFile()->IsBackedByDatabase("ELF");

	memset(&m_symbolTableSection, 0, sizeof(m_symbolTableSection));
	memset(&m_dynamicSymbolTableSection, 0, sizeof(m_dynamicSymbolTableSection));
	memset(&m_dynamicStringTable, 0, sizeof(m_dynamicStringTable));
	memset(&m_dynamicTable, 0, sizeof(m_dynamicTable));
	memset(&m_relocSection, 0, sizeof(m_relocSection));
	memset(&m_relocaSection, 0, sizeof(m_relocaSection));
	memset(&m_tlsSegment, 0, sizeof(m_tlsSegment));
	memset(&m_auxSymbolTable, 0, sizeof(m_auxSymbolTable));
	memset(&m_sectionStringTable, 0, sizeof(m_sectionStringTable));
	memset(&m_sectionOpd, 0, sizeof(m_sectionOpd));

	m_logger->LogInfo("Detected %s endian ELF", m_endian == LittleEndian ? "Little Endian" : "Big Endian");


	if (m_elf32 && (header.sectionHeaderSize != sizeof(Elf32SectionHeader)))
	{
		m_logger->LogWarn(
			"The section header size reported by e_shentsize (0x%lx) is different from the size of Elf32_Shdr (0x%lx). "
			"The parsing proceeds with the size of Elf32_Shdr.",
			header.sectionHeaderSize, sizeof(Elf32SectionHeader));
		header.sectionHeaderSize = sizeof(Elf32SectionHeader);
	}
	else if (!m_elf32 && (header.sectionHeaderSize != sizeof(Elf64SectionHeader)))
	{
		m_logger->LogWarn(
			"The section header size reported by e_shentsize (0x%lx) is different from the size of Elf64_Shdr (0x%lx). "
			"The parsing proceeds with the size of Elf64_Shdr.",
			header.sectionHeaderSize, sizeof(Elf64SectionHeader));
		header.sectionHeaderSize = sizeof(Elf64SectionHeader);
	}

	if (m_elf32 && (header.programHeaderSize != sizeof(Elf32ProgramHeader)))
	{
		m_logger->LogWarn(
			"The program header size reported by e_phentsize (0x%lx) is different from the size of Elf32_Phdr (0x%lx). "
			"The parsing proceeds with the size of Elf32_Phdr.",
			header.programHeaderSize, sizeof(Elf32ProgramHeader));
		header.programHeaderSize = sizeof(Elf32ProgramHeader);
	}
	else if (!m_elf32 && (header.programHeaderSize != sizeof(Elf64ProgramHeader)))
	{
		m_logger->LogWarn(
			"The program header size reported by e_phentsize (0x%lx) is different from the size of Elf64_Phdr (0x%lx). "
			"The parsing proceeds with the size of Elf64_Phdr.",
			header.programHeaderSize, sizeof(Elf64ProgramHeader));
		header.programHeaderSize = sizeof(Elf64ProgramHeader);
	}

	m_entryPoint = header.entry;
	m_sectionHeaderOffset = header.sectionHeaderOffset;
	m_sectionHeaderCount = header.sectionHeaderCount;
	m_programHeaderOffset = header.programHeaderOffset;
	m_programHeaderCount = header.programHeaderCount;
	m_headerFlags = header.flags;
	m_fileSize = data->GetLength();

	m_logger->LogDebug(
		"ELF Header\n"
		"\t%d bits\n"
		"\theader.entry               %016x\n"
		"\theader.programHeaderOffset %016x\n"
		"\theader.sectionHeaderOffset %016x\n"
		"\theader.flags               %016x\n"
		"\theader.headerSize          %016x\n"
		"\theader.programHeaderSize   %016x\n"
		"\theader.programHeaderCount  %016x\n"
		"\theader.sectionHeaderSize   %016x\n"
		"\theader.sectionHeaderCount  %016x\n"
		"\theader.stringTable         %016x\n",
		m_addressSize * 8, header.entry, header.programHeaderOffset, header.sectionHeaderOffset, header.flags,
		header.headerSize, header.programHeaderSize, header.programHeaderCount, header.sectionHeaderSize,
		header.sectionHeaderCount, header.stringTable);

	BinaryReader reader(data);
	reader.SetEndianness(m_endian);

	// Parse program headers
	reader.Seek(header.programHeaderOffset);
	for (size_t i = 0; i < header.programHeaderCount; i++)
	{
		Elf64ProgramHeader progHeader;
		if (m_elf32) // 32-bit ELF
		{
			progHeader.type = reader.Read32();
			progHeader.offset = reader.Read32();
			progHeader.virtualAddress = reader.Read32();
			progHeader.physicalAddress = reader.Read32();
			progHeader.fileSize = reader.Read32();
			progHeader.memorySize = reader.Read32();
			progHeader.flags = reader.Read32();
			progHeader.align = reader.Read32();
		}
		else // 64-bit ELF
		{
			progHeader.type = reader.Read32();
			progHeader.flags = reader.Read32();
			progHeader.offset = reader.Read64();
			progHeader.virtualAddress = reader.Read64();
			progHeader.physicalAddress = reader.Read64();
			progHeader.fileSize = reader.Read64();
			progHeader.memorySize = reader.Read64();
			progHeader.align = reader.Read64();
		}

		m_logger->LogDebug(
			"\tSegment: %d\n"
			"\t\tprogHeader.type            %08x\n"
			"\t\tprogHeader.offset          %08x\n"
			"\t\tprogHeader.virtualAddress  %016x\n"
			"\t\tprogHeader.physicalAddress %016x\n"
			"\t\tprogHeader.fileSize        %016x\n"
			"\t\tprogHeader.memorySize      %016x\n"
			"\t\tprogHeader.flags           %016x\n"
			"\t\tprogHeader.align           %016x\n",
			i, progHeader.type, progHeader.offset, progHeader.virtualAddress, progHeader.physicalAddress,
			progHeader.fileSize, progHeader.memorySize, progHeader.flags, progHeader.align);

		if (!memcmp(m_ident.signature, "\x7f" "CGC", 4))
		{
			// CGC uses physical address for loading
			uint64_t temp = progHeader.virtualAddress;
			progHeader.virtualAddress = progHeader.physicalAddress;
			progHeader.physicalAddress = temp;
		}

		m_programHeaders.push_back(progHeader);

		if (progHeader.type == ELF_PT_DYNAMIC)
			m_dynamicTable = progHeader;
		if (progHeader.type == ELF_PT_TLS)
			m_tlsSegment = progHeader;
	}

	// Parse section headers
	try
	{
		reader.Seek(header.sectionHeaderOffset);
		m_logger->LogDebug("Section List");
		for (size_t i = 0; i < header.sectionHeaderCount; i++)
		{
			Elf64SectionHeader section;
			reader.Seek(header.sectionHeaderOffset + (i * header.sectionHeaderSize));
			if (m_elf32) // 32-bit ELF
			{
				section.name = reader.Read32();
				section.type = reader.Read32();
				section.flags = reader.Read32();
				section.address = reader.Read32();
				section.offset = reader.Read32();
				section.size = reader.Read32();
				section.link = reader.Read32();
				section.info = reader.Read32();
				section.align = reader.Read32();
				section.entrySize = reader.Read32();
			}
			else // 64-bit ELF
			{
				section.name = reader.Read32();
				section.type = reader.Read32();
				section.flags = reader.Read64();
				section.address = reader.Read64();
				section.offset = reader.Read64();
				section.size = reader.Read64();
				section.link = reader.Read32();
				section.info = reader.Read32();
				section.align = reader.Read64();
				section.entrySize = reader.Read64();
			}

			m_elfSections.push_back(section);

			if (section.size > m_fileSize)
			{
				m_logger->LogWarn("Section %lu has a size (0x%lx) larger than file size (0x%lx), skipping creation", i,
					section.size, m_fileSize);
				continue;
			}

			if (section.type == ELF_SHT_SYMTAB)
				m_symbolTableSection = section;
			else if (section.type == ELF_SHT_DYNSYM)
				m_dynamicSymbolTableSection = section;
			else if (section.type == ELF_SHT_STRTAB)
			{
				ApplyTypesToParentStringTable(section);
				if (i == header.stringTable)
				{
					m_sectionStringTable = section;
				}
				continue;
			}

			if (section.flags & ELF_SHF_STRINGS)
				ApplyTypesToParentStringTable(section, false);
		}
	}
	catch (ReadException&)
	{
		// Section headers are not required for a valid ELF, skip errors
		m_logger->LogError("ELF section headers invalid");
	}

	for (size_t i = 0; i < m_elfSections.size(); i++)
	{
		const string scnNameString = ReadStringTable(reader, m_sectionStringTable, m_elfSections[i].name);
		m_logger->LogDebug("\tSection: %d\n"
				"\t\tsection.name      %08x (%s)\n"
				"\t\tsection.type      %08x\n"
				"\t\tsection.flags     %016x\n"
				"\t\tsection.address   %016x\n"
				"\t\tsection.offset    %016x\n"
				"\t\tsection.size      %016x\n"
				"\t\tsection.link      %08x\n"
				"\t\tsection.info      %016x\n"
				"\t\tsection.align     %016x\n"
				"\t\tsection.entrySize %016x",
				i,
				m_elfSections[i].name, scnNameString.c_str(),
				m_elfSections[i].type,
				m_elfSections[i].flags,
				m_elfSections[i].address,
				m_elfSections[i].offset,
				m_elfSections[i].size,
				m_elfSections[i].link,
				m_elfSections[i].info,
				m_elfSections[i].align,
				m_elfSections[i].entrySize
			);

		if (!m_elf32 && m_commonHeader.arch == EM_PPC64 && scnNameString == ".opd")
			m_sectionOpd = m_elfSections[i];
	}

	/* TODO: PPC64 specific entrypoint handling to be moved to architecture extension for ELF */
	if (m_commonHeader.arch == EM_PPC64)
	{
		uint64_t entry;
		if (DerefPpc64Descriptor(reader, m_entryPoint, entry))
		{
			m_logger->LogDebug("PPC64 dereference m_entryPoint=%016x to %016x\n", m_entryPoint, entry);
			m_entryPoint = entry;
		}
		else
		{
			m_logger->LogDebug("PPC64 unable to dereference m_entryPoint=%016x\n", m_entryPoint);
		}
	}
}


ElfView::~ElfView()
{
	for (auto& i : m_relocationInfo)
	{
		auto cur = i.next;
		while (cur)
		{
			auto next = cur->next;
			delete cur;
			cur = next;
		}
	}
}


static BNSymbolBinding TranslateELFBindingType(uint8_t type)
{
	switch (type)
	{
	case ELF_STB_LOCAL: return LocalBinding;
	case ELF_STB_GLOBAL: return GlobalBinding;
	case ELF_STB_WEAK: return WeakBinding;
	default:
	return NoBinding;
	}
}


bool ElfView::ParseSymbolTableEntry(BinaryReader& reader, ElfSymbolTableEntry& entry, uint64_t sym,
	const Elf64SectionHeader& symbolTable, const Elf64SectionHeader& stringTable, bool dynamic)
{
	try
	{
		entry.dynamic = dynamic;
		if (m_elf32)
		{
			reader.Seek(symbolTable.offset + (sym * 16));
			entry.nameOffset = reader.Read32();
			entry.value = reader.Read32();
			entry.size = reader.Read32();
			uint8_t info = reader.Read8();
			entry.type = ELF_ST_TYPE(info);
			entry.binding = TranslateELFBindingType(ELF_ST_BIND(info));
			entry.other = reader.Read8();
			entry.section = reader.Read16();
		}
		else
		{
			reader.Seek(symbolTable.offset + (sym * 24));
			entry.nameOffset = reader.Read32();
			uint8_t info = reader.Read8();
			entry.type = ELF_ST_TYPE(info);
			entry.binding = TranslateELFBindingType(ELF_ST_BIND(info));
			entry.other = reader.Read8();
			entry.section = reader.Read16();
			entry.value = reader.Read64();
			entry.size = reader.Read64();
		}

		if (entry.type == ELF_STT_SECTION)
		{
			if (entry.section < m_elfSections.size())
			{
				entry.name = ReadStringTable(reader, m_sectionStringTable, m_elfSections[entry.section].name);
			}
		}
		else
		{
			entry.name = ReadStringTable(reader, stringTable, entry.nameOffset);
		}
	}
	catch (ReadException&)
	{
		return false;
	}

	m_logger->LogDebug(
		"Symbol: %d - symbolSection.offset: %lx - stringSection.offset: %lx\n"
		"\tnameOffset = %#08lx\n"
		"\ttype       = %#02x\n"
		"\tbinding    = %#02x\n"
		"\tother      = %#02x\n"
		"\tsection    = %#04x\n"
		"\tvalue      = %#012lx\n"
		"\tsize       = %#012lx\n"
		"\tname       = %#s",
		sym, symbolTable.offset, stringTable.offset,
		entry.nameOffset,
		entry.type,
		entry.binding,
		entry.other,
		entry.section,
		entry.value,
		entry.size,
		entry.name.c_str());
	return true;
}

void ElfView::GetRelocEntries(BinaryReader& reader, const vector<Elf64SectionHeader>& sections,
	bool implicit, vector<ELFRelocEntry>& result)
{
	size_t relocSize = m_elf32 ? 8 : 16;
	if (!implicit)
		relocSize += m_elf32 ? 4 : 8;

	for (auto& section : sections)
	{
		for (uint64_t j = 0; j < section.size / relocSize; j++)
		{
			reader.Seek(section.offset + (j * relocSize));
			uint64_t ofs = m_elf32 ? reader.Read32() : reader.Read64();
			uint64_t info = m_elf32 ? reader.Read32() : reader.Read64();
			uint64_t addend = 0;
			if (!implicit)
				addend = m_elf32 ? reader.Read32() : reader.Read64();

			result.push_back(ELFRelocEntry(ofs, info >> (m_elf32 ? 8 : 32), info & (m_elf32 ? 0xff : 0xffffffff),
				addend, section.info, implicit));
		}
	}
}

static bool In(const string& str, const vector<string>& list)
{
	for (auto& a : list)
		if (a == str)
			return true;
	return false;
}

bool ElfView::Init()
{
	std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();
	// Add segments for the program headers
	BinaryReader reader(GetParentView());
	BinaryReader virtualReader(this);

	uint64_t initialImageBase = 0;
	bool initialImageBaseSet = false;
	for (const auto& i : m_programHeaders)
	{
		if ((i.type != ELF_PT_LOAD) || (!i.fileSize))
			continue;

		if (!initialImageBaseSet)
		{
			initialImageBase = i.virtualAddress;
			initialImageBaseSet = true;
		}
		else if (i.virtualAddress < initialImageBase)
			initialImageBase = i.virtualAddress;
	}

	SetOriginalImageBase(initialImageBase);
	uint64_t preferredImageBase = initialImageBase;
	Ref<Settings> viewSettings = Settings::Instance();
	m_extractMangledTypes = viewSettings->Get<bool>("analysis.extractTypesFromMangledNames", this);
	m_simplifyTemplates = viewSettings->Get<bool>("analysis.types.templateSimplifier", this);

	Ref<Settings> settings = GetLoadSettings(GetTypeName());
	if (settings)
	{
		if (settings->Contains("loader.imageBase"))
			preferredImageBase = settings->Get<uint64_t>("loader.imageBase", this);

		if (settings->Contains("loader.platform"))
		{
			Ref<Platform> platformOverride = Platform::GetByName(settings->Get<string>("loader.platform", this));
			if (platformOverride)
			{
				m_plat = platformOverride;
				m_arch = m_plat->GetArchitecture();
			}
		}
	}

	int64_t imageBaseAdjustment = 0;
	if (!initialImageBase)
		imageBaseAdjustment = preferredImageBase;
	else if (initialImageBase <= preferredImageBase)
		imageBaseAdjustment = preferredImageBase - initialImageBase;
	else
		imageBaseAdjustment = -(int64_t)(initialImageBase - preferredImageBase);

	m_entryPoint = m_entryPoint + imageBaseAdjustment;

	BeginBulkAddSegments();
	for (auto& i : m_programHeaders)
	{
		uint64_t adjustedVirtualAddr = i.virtualAddress + imageBaseAdjustment;

		if (i.type == ELF_PT_LOAD) // || i.type == ELF_PT_GNU_RELRO)
		{
			uint32_t flags = 0;
			if (i.flags & 1)
				flags |= SegmentExecutable;
			if (i.flags & 2)
				flags |= SegmentWritable;
			if (i.flags & 4)
				flags |= SegmentReadable;
			AddAutoSegment(adjustedVirtualAddr, i.memorySize, i.offset, i.fileSize, flags);
		}

		// Create sections for the program headers with the standard section names. This will ensure that
		// the standard name for sections such as .dynamic will always refer to what the loader actually uses.
		if (i.type == ELF_PT_DYNAMIC)
		{
			uint64_t entrySize = m_elf32 ? 8 : 16;

			bool foundMatch = false;
			for (size_t j = 1; j < m_elfSections.size(); j++)
			{
				uint64_t adjustedSectionAddr = m_elfSections[j].address + imageBaseAdjustment;

				if (m_elfSections[j].type != ELF_SHT_DYNAMIC)
					continue;
				if (adjustedSectionAddr != adjustedVirtualAddr)
					continue;
				if (m_elfSections[j].size != i.memorySize)
					continue;
				if (m_elfSections[j].entrySize != entrySize)
					continue;
				if (ReadStringTable(reader, m_sectionStringTable, m_elfSections[j].name) != ".dynamic")
					continue;
				foundMatch = true;
				break;
			}

			if (!foundMatch)
				AddAutoSection(".dynamic", adjustedVirtualAddr, i.memorySize, ReadOnlyDataSectionSemantics, "DYNAMIC", i.align, entrySize);
		}
		else if (i.type == ELF_PT_INTERP)
		{
			bool foundMatch = false;
			for (size_t j = 1; j < m_elfSections.size(); j++)
			{
				uint64_t adjustedSectionAddr = m_elfSections[j].address + imageBaseAdjustment;

				if (m_elfSections[j].type != ELF_SHT_PROGBITS)
					continue;
				if (adjustedSectionAddr != adjustedVirtualAddr)
					continue;
				if (m_elfSections[j].size != i.memorySize)
					continue;
				if (ReadStringTable(reader, m_sectionStringTable, m_elfSections[j].name) != ".interp")
					continue;
				foundMatch = true;
				break;
			}

			if (!foundMatch)
				AddAutoSection(".interp", adjustedVirtualAddr, i.memorySize, ReadOnlyDataSectionSemantics, "PROGBITS", i.align);

			DefineDataVariable(adjustedVirtualAddr, Type::ArrayType(Type::IntegerType(1, true), i.fileSize));
			DefineAutoSymbol(new Symbol(DataSymbol, "__elf_interp", adjustedVirtualAddr, LocalBinding));
		}
	}

	EndBulkAddSegments();

	// Gather names for the sections
	vector<string> sectionNames {""};
	for (size_t i = 1; i < m_elfSections.size(); i++)
		sectionNames.push_back(ReadStringTable(reader, m_sectionStringTable, m_elfSections[i].name));
	sectionNames = GetUniqueSectionNames(sectionNames);

	// Add sections to the view
	vector<Elf64SectionHeader> dynRelocSections, dynRelocASections;
	vector<Elf64SectionHeader> relocSections, relocASections;
	Elf64SectionHeader symbolTableSection;

	uint64_t segmentStart = 0;
	for (size_t i = 1; i < m_elfSections.size(); i++)
	{
		string type;
		string linkedSection, infoSection;
		switch (m_elfSections[i].type)
		{
		case ELF_SHT_PROGBITS:
			type = "PROGBITS";
			break;
		case ELF_SHT_SYMTAB:
			type = "SYMTAB";
			symbolTableSection = m_elfSections[i];
			break;
		case ELF_SHT_STRTAB:
			type = "STRTAB";
			break;
		case ELF_SHT_RELA:
			type = "RELA";
			relocASections.push_back(m_elfSections[i]);
			break;
		case ELF_SHT_REL:
			type = "REL";
			relocSections.push_back(m_elfSections[i]);
			break;
		case ELF_SHT_HASH:
			type = "HASH";
			break;
		case ELF_SHT_DYNAMIC:
			type = "DYNAMIC";
			break;
		case ELF_SHT_NOTE:
			type = "NOTE";
			break;
		case ELF_SHT_NOBITS:
			type = "NOBITS";
			break;
		case ELF_SHT_SHLIB:
			type = "SHLIB";
			break;
		case ELF_SHT_DYNSYM:
			type = "DYNSYM";
			break;
		default:
			break;
		}

		// Add sections that aren't in the virtual address space only to the raw parent view
		if (!(m_elfSections[i].flags & ELF_SHF_ALLOC))
		{
			if (m_elfSections[i].size != 0 && m_elfSections[i].type != ELF_SHT_NOBITS)
				GetParentView()->AddAutoSection(sectionNames[i], m_elfSections[i].offset, m_elfSections[i].size, DefaultSectionSemantics,
					type, m_elfSections[i].align, m_elfSections[i].entrySize, linkedSection, infoSection, m_elfSections[i].info);
			continue;
		}

		if (m_elfSections[i].type == ELF_SHT_STRTAB)
			ApplyTypesToStringTable(m_elfSections[i], imageBaseAdjustment);
		else if (m_elfSections[i].flags & ELF_SHF_STRINGS)
			ApplyTypesToStringTable(m_elfSections[i], imageBaseAdjustment, false);

		if (m_elfSections[i].link < m_elfSections.size())
			linkedSection = sectionNames[m_elfSections[i].link];

		BNSectionSemantics semantics = DefaultSectionSemantics;
		vector<string> readOnlyCodeSectionNames = {".text", ".init", ".fini"};
		vector<string> readWriteDataSectionNames = {".data", ".bss"};
		vector<string> readOnlyDataSectionNames = {".rodata", ".dynamic", ".dynsym", ".dynstr", ".ehframe",
			".ctors", ".dtors", ".got", ".got2", ".data.rel.ro", ".gnu.hash"};
		if ((m_elfSections[i].flags & ELF_SHF_EXECINSTR) ||  In(sectionNames[i], readOnlyCodeSectionNames))
			semantics = ReadOnlyCodeSectionSemantics;
		else if (!(m_elfSections[i].flags & ELF_SHF_WRITE) || In(sectionNames[i], readOnlyDataSectionNames))
			semantics = ReadOnlyDataSectionSemantics;
		else if ((m_elfSections[i].flags & ELF_SHF_WRITE) || In(sectionNames[i], readWriteDataSectionNames))
			semantics = ReadWriteDataSectionSemantics;

		if (m_elfSections[i].size != 0)
		{
			if (m_programHeaders.size() == 0)
			{
				// We have an object file so we'll just create segments for the sections
				uint32_t flags = 0;
				if (semantics == ReadOnlyCodeSectionSemantics)
					flags = SegmentReadable | SegmentExecutable;
				else if (semantics == ReadWriteDataSectionSemantics)
					flags = SegmentReadable | SegmentWritable;
				else if (semantics == ReadOnlyDataSectionSemantics)
					flags = SegmentReadable;
				m_elfSections[i].address = segmentStart;
				size_t size = m_elfSections[i].type == ELF_SHT_NOBITS ? 0 : m_elfSections[i].size;
				uint64_t adjustedSectionAddr = m_elfSections[i].address + imageBaseAdjustment;
				AddAutoSegment(adjustedSectionAddr, m_elfSections[i].size, m_elfSections[i].offset, size, flags);
				segmentStart += ((m_elfSections[i].size + 15) & ~15);
			}
			else if ((m_elfSections[i].address + m_elfSections[i].size + imageBaseAdjustment) > GetEnd() || ((m_elfSections[i].address + imageBaseAdjustment) < GetStart()))
			{
				LogWarn("Section %s is outside of the address space of the file and will not be added", sectionNames[i].c_str());
				continue;
			}

			uint64_t adjustedVirtualAddr = m_elfSections[i].address + imageBaseAdjustment;
			AddAutoSection(sectionNames[i], adjustedVirtualAddr, m_elfSections[i].size, semantics, type, m_elfSections[i].align,
				m_elfSections[i].entrySize, linkedSection, infoSection, m_elfSections[i].info);
			if (m_elfSections[i].type != ELF_SHT_NOBITS)
				GetParentView()->AddAutoSection(sectionNames[i], m_elfSections[i].offset, m_elfSections[i].size, DefaultSectionSemantics, type, m_elfSections[i].align, m_elfSections[i].entrySize, linkedSection, infoSection, m_elfSections[i].info);
		}
	}

	// Apply architecture and platform
	if (!m_arch)
	{
		switch (m_commonHeader.arch)
		{
		case 3:
			m_logger->LogError("Support for ELF architecture 'x86' is not present");
			break;
		case 8:
			#ifndef DEMO_EDITION
			m_logger->LogError("Support for ELF architecture 'mips' is not present");
			#else
			m_logger->LogError("Binary Ninja free does not support ELF architecture 'mips'. "
							   "Purchase Binary Ninja to unlock all features.");
			#endif
			break;
		case 20:
			#ifndef DEMO_EDITION
			m_logger->LogError("Support for ELF architecture 'ppc' is not present");
			#else
			m_logger->LogError("Binary Ninja free does not support ELF architecture 'ppc'. "
							   "Purchase Binary Ninja to unlock all features.");
			#endif
			break;
		case 21:
			#ifndef DEMO_EDITION
			m_logger->LogError("Support for ELF architecture 'ppc64' is not present");
			#else
			m_logger->LogError("Binary Ninja free does not support ELF architecture 'ppc64'. "
							   "Purchase Binary Ninja to unlock all features.");
			#endif
			break;
		case 40:
			m_logger->LogError("Support for ELF architecture 'armv7' is not present");
			break;
		case 62:
			m_logger->LogError("Support for ELF architecture 'x86_64' is not present");
			break;
		case 183:
			#ifndef DEMO_EDITION
			m_logger->LogError("Support for ELF architecture 'arm64' is not present");
			#else
			m_logger->LogError("Binary Ninja free does not support ELF architecture 'arm64'. "
							   "Purchase Binary Ninja to unlock all features.");
			#endif
			break;
		default:
			m_logger->LogError("ELF architecture %d is not supported", m_commonHeader.arch);
			break;
		}

		if (!m_parseOnly)
			m_logger->LogWarn("Unable to determine architecture. Please open the file with options and select a valid architecture.");
		return false;
	}

	// Add the entry point as a function if the architecture is supported
	uint64_t entryPointAddress = m_entryPoint;
	Ref<Architecture> entryPointArch = m_arch->GetAssociatedArchitectureByAddress(entryPointAddress);
	SetDefaultArchitecture(entryPointArch);
	GetParentView()->SetDefaultArchitecture(entryPointArch);

	Ref<Platform> platform = m_plat ? m_plat : g_elfViewType->GetPlatform(m_ident.os, m_arch);
	if (platform && (entryPointArch != m_arch))
		platform = platform->GetRelatedPlatform(entryPointArch);
	if (!platform)
		platform = entryPointArch->GetStandalonePlatform();

	SetDefaultPlatform(platform);
	GetParentView()->SetDefaultPlatform(platform);

	// Finished for parse only mode
	if (m_parseOnly)
	{
		m_stringTableCache.clear();
		return true;
	}

	// Set reader endianness
	reader.SetEndianness(m_endian);
	virtualReader.SetEndianness(m_endian);

	// FIXME: MIPS specific GOT entries should be done in the MIPS plugin, once there is a way to have
	// ELF parsing extensions in an architecture plugin
	uint64_t gotStart = 0;
	uint64_t localMipsSyms = 0;
	uint64_t firstMipsSym = 0;
	uint64_t baseAddress = GetStart();
	vector<uint64_t> neededLibraries;
	bool mipsSymValid = false;
	// FIXME: ARM specific GOT entries should be done in the MIPS plugin, as above
	bool isArmV7 = m_arch->GetName() == "armv7";
	vector<uint64_t> tlsModuleStarts;
	vector<uint64_t> tlsOffsets;

	// Parse dynamic table
	if (auto dynSeg = GetSegmentAt(m_dynamicTable.virtualAddress + imageBaseAdjustment); dynSeg && m_dynamicTable.virtualAddress)
	{
		try
		{
			uint64_t adjustedVirtualAddr = m_dynamicTable.virtualAddress + imageBaseAdjustment;
			reader.Seek(adjustedVirtualAddr - dynSeg->GetStart() + dynSeg->GetDataOffset());

			Elf64SectionHeader plt;
			memset(&plt, 0, sizeof(plt));
			uint64_t pltType = ELF_DT_RELA;
			bool end = false;
			uint64_t entrySize = m_elf32 ? 8 : 16;
			size_t i = 0;
			while (!end)
			{
				uint64_t tag, value;
				if (i >= m_dynamicTable.fileSize)
				{
					// Prevent reading past end of dynamic table in file
					end = true;
					break;
				}

				if (m_elf32) // 32-bit ELF
				{
					tag = reader.Read32();
					value = reader.Read32();
					i += 8;
				}
				else // 64-bit ELF
				{
					tag = reader.Read64();
					value = reader.Read64();
					i += 16;
				}

				switch (tag)
				{
				case ELF_DT_NULL:
					end = true;
					m_numDynamicTableEntries = i ? i / entrySize : 0;
					break;
				case ELF_DT_NEEDED:
					neededLibraries.push_back(value);
					break;
				case ELF_DT_PLTREL:
					pltType = value;
					break;
				case ELF_DT_JMPREL:
					plt.offset = value + imageBaseAdjustment;
					break;
				case ELF_DT_PLTRELSZ:
					plt.size = value;
					break;
				case ELF_DT_STRTAB:
					m_dynamicStringTable.offset = value + imageBaseAdjustment;
					break;
				case ELF_DT_SYMTAB:
					m_auxSymbolTable.offset = value + imageBaseAdjustment;
					break;
				case ELF_DT_SYMENT:
					m_auxSymbolTableEntrySize = value;
					break;
				case ELF_DT_INIT:
				case ELF_DT_FINI:
				{
					uint64_t target = value + imageBaseAdjustment;
					string autoName = (tag == ELF_DT_INIT) ? "_init" : "_fini";
					DefineAutoSymbol(new Symbol(FunctionSymbol, autoName, target, NoBinding));
					Ref<Platform> targetPlatform = platform->GetAssociatedPlatformByAddress(target);
					AddFunctionForAnalysis(targetPlatform, target);
					break;
				}
				case ELF_DT_HASH:
					m_hashHeader = value + imageBaseAdjustment;
					break;
				case ELF_DT_GNU_HASH:
					m_gnuHashHeader = value + imageBaseAdjustment;
					break;
				case ELF_DT_RELA:
					m_relocaSection.offset = value + imageBaseAdjustment;
					break;
				case ELF_DT_RELASZ:
					m_relocaSection.size = value;
					break;
				case ELF_DT_RELAENT:
					m_relocaSection.entrySize = value;
					break;
				case ELF_DT_STRSZ:
					m_dynamicStringTable.size = value;
					break;
				case ELF_DT_REL:
					m_relocSection.offset = value + imageBaseAdjustment;
					break;
				case ELF_DT_RELSZ:
					m_relocSection.size = value;
					break;
				case ELF_DT_RELENT:
					m_relocSection.entrySize = value;
					break;
				case ELF_DT_PLTGOT:
					gotStart = value + imageBaseAdjustment;
					break;
				case ELF_DT_MIPS_SYMTABNO:
					m_auxSymbolTable.size = m_elf32 ? value * 16 : value * 24;
					break;
				case ELF_DT_MIPS_LOCAL_GOTNO:
					localMipsSyms = value;
					break;
				case ELF_DT_MIPS_GOTSYM:
					firstMipsSym = value;
					mipsSymValid = true;
					break;
				case ELF_DT_MIPS_BASE_ADDRESS:
					baseAddress = value + imageBaseAdjustment;
					break;
				default:
					break;
				}
			}

			vector<Ref<Metadata>> libraries;
			vector<Ref<Metadata>> libraryFound;
			for (auto& libNameOffset : neededLibraries)
			{
				const string libName = ReadStringTable(virtualReader, m_dynamicStringTable, libNameOffset);
				if (!GetExternalLibrary(libName))
				{
					AddExternalLibrary(libName, {}, true);
				}
				libraries.push_back(new Metadata(string(libName)));
				Ref<TypeLibrary> typeLib = GetTypeLibrary(libName);
				if (!typeLib)
				{
					vector<Ref<TypeLibrary>> typeLibs = platform->GetTypeLibrariesByName(libName);
					if (typeLibs.size())
					{
						typeLib = typeLibs[0];
						AddTypeLibrary(typeLib);

						m_logger->LogDebug("elf: adding type library for '%s': %s (%s)", libName.c_str(), typeLib->GetName().c_str(),
							typeLib->GetGuid().c_str());
					}
				}

				if (typeLib)
					libraryFound.push_back(new Metadata(typeLib->GetName()));
				else
					libraryFound.push_back(new Metadata(string("")));
			}
			StoreMetadata("Libraries", new Metadata(libraries), true);
			StoreMetadata("LibraryFound", new Metadata(libraryFound), true);

			if (m_relocaSection.size > 0)
			{
				bool alreadyExists = false;
				for (auto& relSec : relocASections)
					if (relSec.offset == m_relocaSection.offset)
						alreadyExists = true;
				if (!alreadyExists)
				{
					dynRelocASections.push_back(m_relocaSection);
					AddAutoSection(
						".dynamic_rela", m_relocaSection.offset, m_relocaSection.size, ReadOnlyDataSectionSemantics);
				}
			}
			if (plt.size > 0)
			{
				if (pltType == ELF_DT_REL)
				{
					bool alreadyExists = false;
					for (auto& relSec : relocSections)
						if ((relSec.address + imageBaseAdjustment) == plt.offset)
							alreadyExists = true;
					if (!alreadyExists)
					{
						dynRelocSections.push_back(plt);
						AddAutoSection(".dynamic_jmprel", plt.offset, plt.size, ReadOnlyDataSectionSemantics);
					}
				}
				else
				{
					bool alreadyExists = false;
					for (auto& relSec : relocASections)
						if ((relSec.address + imageBaseAdjustment) == plt.offset)
							alreadyExists = true;
					if (!alreadyExists)
					{
						dynRelocASections.push_back(plt);
						AddAutoSection(".dynamic_jmprel", plt.offset, plt.size, ReadOnlyDataSectionSemantics);
					}
				}
			}
			if (m_relocSection.size > 0)
			{
				bool alreadyExists = false;
				for (auto& relSec : relocSections)
					if ((relSec.address + imageBaseAdjustment) == m_relocSection.offset)
						alreadyExists = true;
				if (!alreadyExists)
				{
					dynRelocSections.push_back(m_relocSection);
					AddAutoSection(
						".dynamic_rel", m_relocSection.offset, m_relocSection.size, ReadOnlyDataSectionSemantics);
				}
			}
		}
		catch (ReadException&)
		{
			m_logger->LogError("ELF dynamic table invalid");
		}
	}

	// Parse symbol table
	vector<ElfSymbolTableEntry> symbolTable, dynamicSymbolTable;
	try
	{
		if ((m_symbolTableSection.size > 0) && (m_symbolTableSection.link < m_elfSections.size()))
		{
			symbolTable = ParseSymbolTable(reader, m_symbolTableSection, m_elfSections[m_symbolTableSection.link], false);
		}

		if ((m_dynamicSymbolTableSection.size > 0) && (m_dynamicSymbolTableSection.link < m_elfSections.size()))
		{
			dynamicSymbolTable = ParseSymbolTable(reader, m_dynamicSymbolTableSection,
				m_elfSections[m_dynamicSymbolTableSection.link], true);
		}
	}
	catch (ReadException&)
	{
		// Symbol table is not critical to execution, skip errors
		m_logger->LogError("ELF symbol table invalid");
	}

	vector<ELFRelocEntry> relocs;
	try
	{
		GetRelocEntries(virtualReader, dynRelocSections, true, relocs);
		GetRelocEntries(virtualReader, dynRelocASections, false, relocs);
		GetRelocEntries(reader, relocSections, true, relocs);
		GetRelocEntries(reader, relocASections, false, relocs);
		for (auto& reloc : relocs)
			reloc.offset += imageBaseAdjustment;
	}
	catch (ReadException&)
	{
		// Skip errors in relocation tables
		m_logger->LogError("ELF relocation table invalid");
	}

	BeginBulkModifySymbols();

	vector<ElfSymbolTableEntry> auxSymbolTable;
	try
	{
		if (!m_auxSymbolTableEntrySize)
			m_auxSymbolTableEntrySize = m_elf32 ? 16 : 24;

		// Parse and create types for ELF hash table
		if (m_hashHeader)
		{
			virtualReader.Seek(m_hashHeader);
			uint32_t nbucket = virtualReader.Read32();
			uint32_t nchain = virtualReader.Read32();
			m_auxSymbolTable.size = m_auxSymbolTableEntrySize * nchain;
			auxSymbolTable = ParseSymbolTable(virtualReader, m_auxSymbolTable, m_dynamicStringTable, true);

			StructureBuilder hashTableBuilder;
			hashTableBuilder.AddMember(Type::IntegerType(4, false), "nbucket");
			hashTableBuilder.AddMember(Type::IntegerType(4, false), "nchain");
			hashTableBuilder.AddMember(Type::ArrayType(Type::IntegerType(4, false), nbucket), "buckets");
			hashTableBuilder.AddMember(Type::ArrayType(Type::IntegerType(4, false), nchain), "chains");
			Ref<Structure> hashTableStruct = hashTableBuilder.Finalize();
			Ref<Type> hashTableType = Type::StructureType(hashTableStruct);
			QualifiedName hashTableName = string("Elf_HashTable");
			const string hashTableTypeId = Type::GenerateAutoTypeId("elf", hashTableName);
			QualifiedName hashTableTypeName = DefineType(hashTableTypeId, hashTableName, hashTableType);
			DefineDataVariable(m_hashHeader, Type::NamedType(this, hashTableTypeName));
			DefineAutoSymbol(new Symbol(DataSymbol, "__elf_hash_table", m_hashHeader, NoBinding));

			// Gratuitously create sections for the symbol and string tables if none exist
			if (!GetSectionsAt(m_auxSymbolTable.offset).size())
				AddAutoSection(".dynamic_symtab", m_auxSymbolTable.offset, m_auxSymbolTable.size, ReadOnlyDataSectionSemantics);
			if (!GetSectionsAt(m_dynamicStringTable.offset).size())
				AddAutoSection(".dynamic_strtab", m_dynamicStringTable.offset, m_dynamicStringTable.size, ReadOnlyDataSectionSemantics);
		}

		// Parse and create types for ELF GNU hash table
		if (m_gnuHashHeader)
		{
			// try to extract dynamic symbol table size from section information if it exists
			if (!m_auxSymbolTable.size)
			{
				auto sections = GetSectionsAt(m_auxSymbolTable.offset);
				if (sections.size() && (sections[0]->GetStart() == m_auxSymbolTable.offset))
					m_auxSymbolTable.size = sections[0]->GetLength();
				else
				{
					// TODO section information not available; calculate the dynamic symbol table size from the gnu hash table
				}
			}
		}
	}
	catch (ReadException&)
	{
		// Skip errors in hash tables
		m_logger->LogError("ELF hash/symbol table parsing failed");
	}

	try
	{
		if (mipsSymValid && (gotStart != 0))
		{
			for (size_t i = 2; i < localMipsSyms; i++)
			{
				m_gotEntryLocations.emplace(gotStart + i * (m_elf32 ? 4 : 8));
			}
			for (uint64_t i = firstMipsSym; i < (m_auxSymbolTable.size / (m_elf32 ? 16 : 24)); i++)
			{
				uint64_t gotEntry = gotStart + ((localMipsSyms + i - firstMipsSym) * (m_elf32 ? 4 : 8));

				ElfSymbolTableEntry entry;
				if (!ParseSymbolTableEntry(virtualReader, entry, i, m_auxSymbolTable, m_dynamicStringTable, true))
					continue;
				// TODO dynamic symbol table already parsed above; don't add duplicate entries
				if (!m_hashHeader)
					auxSymbolTable.push_back(entry);
				switch (entry.type)
				{
				case ELF_STT_OBJECT:
				case ELF_STT_NOTYPE:
					if (entry.section != ELF_SHN_UNDEF)
						DefineElfSymbol(DataSymbol, entry.name, gotEntry, true, entry.binding, 4, Type::PointerType(
							GetDefaultPlatform()->GetArchitecture(), Type::VoidType())->WithConfidence(BN_FULL_CONFIDENCE));
					else
					{
						bool relocationExists = false;
						for (auto& reloc : relocs)
						{
							if (reloc.offset == gotEntry)
							{
								relocationExists = true;
								break;
							}
						}
						if (!relocationExists)
						{
							int relocType = m_arch->GetAddressSize() == 4 ? 126 /* R_MIPS_COPY */ : 125 /* R_MIPS64_COPY */;
							relocs.push_back(ELFRelocEntry(gotEntry, i, relocType, 0, 0, false));
						}
						DefineElfSymbol(ImportAddressSymbol, entry.name, gotEntry, true, entry.binding, entry.size);
					}
					break;
				case ELF_STT_FUNC:
					if (entry.section != ELF_SHN_UNDEF)
						DefineElfSymbol(DataSymbol, entry.name, gotEntry, true, entry.binding, 4,
							Type::PointerType(GetDefaultPlatform()->GetArchitecture(),
								Type::FunctionType(Type::IntegerType(GetDefaultPlatform()->GetArchitecture()->GetAddressSize(), true),
									GetDefaultPlatform()->GetDefaultCallingConvention(), vector<FunctionParameter>())->WithConfidence(0)));
					else
					{
						bool relocationExists = false;
						for (auto& reloc : relocs)
						{
							if (reloc.offset == gotEntry)
							{
								relocationExists = true;
								break;
							}
						}
						if (!relocationExists)
						{
							int relocType = m_arch->GetAddressSize() == 4 ? 127 /*R_MIPS_JUMP_SLOT*/ : 125 /* R_MIPS64_COPY */;
							relocs.push_back(ELFRelocEntry(gotEntry, i, relocType, 0, 0, false));
						}
						DefineElfSymbol(ImportAddressSymbol, entry.name, gotEntry, true, entry.binding, entry.size);
						// TODO for now create associated PLT entry if it exists. At some point we could extend the detection in RecognizeELFPLTEntries in arch_mips.
						Ref<Symbol> sym = GetSymbolByAddress(gotEntry);
						if (entry.value && sym && (sym->GetType() == ImportAddressSymbol))
						{
							uint64_t adjustedAddress = entry.value + imageBaseAdjustment;
							Ref<Platform> targetPlatform = platform->GetAssociatedPlatformByAddress(adjustedAddress);
							Ref<Function> func = AddFunctionForAnalysis(targetPlatform, adjustedAddress);
							if (func)
							{
								Ref<Symbol> funcSym = new Symbol(ImportedFunctionSymbol,
										sym->GetShortName(), sym->GetFullName(), sym->GetRawName(),
										adjustedAddress, NoBinding, sym->GetNameSpace(), sym->GetOrdinal());
								DefineAutoSymbol(funcSym);
								func->ApplyImportedTypes(funcSym);
							}
						}
					}
					break;
				default:
					m_logger->LogDebug("ELF symbol type of %d not handled.", entry.type);
					break;
				}
			}
		}
	}
	catch (ReadException&)
	{
		// Symbol table is not critical to execution, skip errors
		m_logger->LogError("ELF symbol table invalid");
	}

	// No longer need to look up symbols during creation, start a parallelized queue for
	// demangling and preparing symbols.
	m_symbolQueue = new SymbolQueue();

	// Now define symbols and resolve relocations
	vector<ElfSymbolTableEntry> combinedSymbolTable;
	if (symbolTable.size() > 1)
		combinedSymbolTable.insert(combinedSymbolTable.end(), symbolTable.begin() + 1, symbolTable.end());
	if (dynamicSymbolTable.size() > 1)
		combinedSymbolTable.insert(combinedSymbolTable.end(), dynamicSymbolTable.begin() + 1, dynamicSymbolTable.end());
	if (auxSymbolTable.size() > 1)
		combinedSymbolTable.insert(combinedSymbolTable.end(), auxSymbolTable.begin() + 1, auxSymbolTable.end());

	// Walk the symbol table a first time to collect the information we need to create a .common section
	size_t commonSectionSize = 0;
	for (auto entry = combinedSymbolTable.begin(); entry != combinedSymbolTable.end(); entry++)
	{
		if (entry->section == ELF_SHN_COMMON)
		{
			// account for required alignment, stored in entry->value;
			auto alignedExistingSize = commonSectionSize + (entry->value - 1);
			alignedExistingSize &= ~(entry->value - 1);
			commonSectionSize = alignedExistingSize + entry->size;
		}
	}

	// If the common section exists create a mock segment/section.
	size_t commonSegmentStartAddr = 0;
	if (commonSectionSize > 0) {
		// Find the end of the existing segment definitions to stick the SHN_COMMON segment
		for (const auto& segment : GetSegments()) {
			if (commonSegmentStartAddr < segment->GetEnd()) {
				commonSegmentStartAddr = segment->GetEnd();
			}
		}
		// Align the common segment to 16 bytes
		commonSegmentStartAddr = (commonSegmentStartAddr + 0xf) & (~0xf);
		AddAutoSegment(commonSegmentStartAddr, commonSectionSize, 0, 0, SegmentReadable | SegmentWritable);
		AddAutoSection(".common", commonSegmentStartAddr, commonSectionSize, ReadWriteDataSectionSemantics);
	}

	size_t commonSegmentOffset = 0;
	for (auto entry = combinedSymbolTable.begin(); entry != combinedSymbolTable.end(); entry++)
	{
		if (entry->section == ELF_SHN_COMMON)
		{
			// Common symbols are special as their entry value holds the alignment of the entry instead of an offset.
			auto alignedExistingOffset = commonSegmentOffset + (entry->value - 1);
			alignedExistingOffset &= ~(entry->value - 1);
			DefineElfSymbol(DataSymbol, entry->name, commonSegmentStartAddr + alignedExistingOffset, false, entry->binding, entry->size);
			commonSegmentOffset = alignedExistingOffset + entry->size;
			continue;
		}

		if (m_objectFile)
		{
			if (entry->section >= m_elfSections.size())
				continue;

			// Object files "entry.value" is section relative
			uint64_t adjustedSectionAddr = m_elfSections[entry->section].address + imageBaseAdjustment;
			auto secs = GetSectionsAt(adjustedSectionAddr);
			if (secs.size() < 1)
				continue;

			entry->value += secs[0]->GetStart();
		}
		else
			entry->value += imageBaseAdjustment;

		if (entry->section == ELF_SHN_UNDEF)
		{
			DefineElfSymbol(ExternalSymbol, entry->name, 0, false, entry->binding, entry->size);
		}
		else
		{
			switch (entry->type)
			{
			case ELF_STT_GNU_IFUNC:
				// Only handle this symbol type if the platform is a linux. Otherwise, we don't know what it is.
				if (GetDefaultPlatform()->GetName().rfind("linux", 0) != 0)
					goto unknownType;
				DefineElfSymbol(FunctionSymbol, entry->name, entry->value, false, entry->binding);
				break;
			case ELF_STT_FUNC:
				DefineElfSymbol(FunctionSymbol, entry->name, entry->value, false, entry->binding);
				break;
			case ELF_STT_TLS:
				/* - only create Binja symbols for .symtab (not .dynsym) symbols
				   - ignore mapping symbols, all is assumed data
				   - ignore 0-length symbols (like _TLS_MODULE_BASE_) that are just informative */
				if (entry->dynamic || entry->size == 0 || entry->name == "$d")
				/* is the value a valid offset in the TLS template? */
				if (m_tlsSegment.virtualAddress == 0 || (entry->value + entry->size) > m_tlsSegment.memorySize)
					break;
				/* the value is the offset into the TLS template, specified by program header type 7 (PT_TLS) */
				DefineElfSymbol(DataSymbol, entry->name, m_tlsSegment.virtualAddress + entry->value, false, entry->binding, entry->size);
				break;
			case ELF_STT_NOTYPE:
				// TODO: ARM specific local entry handling to be moved to architecture extension for ELF
				if (entry->binding == LocalBinding && In(m_arch->GetName(), {"aarch64", "armv7", "armv7eb", "thumb2", "thumb2eb"}))
				{
					// ARM Mapping Symbols
					// $a labels the first byte of a sequence of ARM instructions. Its type is STT_FUNC.
					// $b labels a Thumb BL instruction. Its type is STT_FUNC.
					// $d labels the first byte of a sequence of data items. Its type is STT_OBJECT.
					// $f labels a function pointer constant (static pointer to code). Its type is STT_OBJECT.
					// $t labels the first byte of a sequence of Thumb instructions. Its type is STT_FUNC.
					// $*.<symbolName> is an optional long form

					// AArch64 Mapping Symbols
					// $x labels start of sequence of A64 instructions
					// $d labels start of sequence of data items
					// $*.<symbolName> is an optional long form
					bool isMappingSymbol = false;
					bool isMappingFunctionSymbol = false;
					string entryName(entry->name);
					uint64_t target = entry->value;
					if (m_arch->GetName() == "aarch64")
					{
						if (!entryName.rfind("$x", 0))
							isMappingSymbol = isMappingFunctionSymbol = true;
						else if (!entryName.rfind("$d", 0))
							isMappingSymbol = true;
					}
					else
					{
						if (!entryName.rfind("$a", 0))
							isMappingSymbol = isMappingFunctionSymbol = true;
						else if (!entryName.rfind("$b", 0) || !entryName.rfind("$t", 0))
						{
							target |= 1;
							isMappingSymbol = isMappingFunctionSymbol = true;
						}
						else if (!entryName.rfind("$d", 0) || !entryName.rfind("$f", 0))
							isMappingSymbol = true;
					}

					if (isMappingSymbol)
					{
						if (!m_elfSections[entry->section].address) // only add artifacts for mapped sections
							break;

						// Note: It appears that several '$a' or '$t' mapping symbols to not always indicate function starts. Occasionally, an address is marked
						// immediately after a literal pool which is not a function. We explicitly allow mapping symbols for .plt sections for now.
						if (isMappingFunctionSymbol && (sectionNames[entry->section] == ".plt"))
						{
							Ref<Platform> targetPlatform = platform->GetAssociatedPlatformByAddress(target);
							AddFunctionForAnalysis(targetPlatform, target);
						}
						// else // TODO $d and %f
						// 	m_logger->LogError("TODO: %s %p", entryName.c_str(), entry->value);

						// handle long form symbols
						if (auto pos = entryName.find(".", 2); (pos != std::string::npos))
						{
							// These mapping symbols do not define actual names
							if (entryName[0] == '$' && (entryName[1] == 'x' || entryName[1] == 'a' || entryName[1] == 'd'  || entryName[1] == 't'))
								continue;
							entryName = entryName.substr(pos + 1);
							if (entryName.size())
								DefineElfSymbol(isMappingFunctionSymbol ? FunctionSymbol : DataSymbol, entryName, entry->value, false, entry->binding, entry->size);
						}
						break;
					}
				}
				DefineElfSymbol(DataSymbol, entry->name, entry->value, false, entry->binding, entry->size);
				break;
			case ELF_STT_OBJECT:
				DefineElfSymbol(DataSymbol, entry->name, entry->value, false, entry->binding, entry->size);
				break;
			default:
			unknownType:
				m_logger->LogDebug("ELF symbol type of %d not handled.", entry->type);
				break;
			}
		}
	}

	ParseMiniDebugInfo();

	// Process the queued symbols
	m_symbolQueue->Process();
	delete m_symbolQueue;
	m_symbolQueue = nullptr;

	EndBulkModifySymbols();

	auto relocHandler = m_arch->GetRelocationHandler("ELF");
	if (relocHandler)
	{
		try
		{
			for (auto& reloc: relocs)
			{
				BNRelocationInfo relocInfo;
				memset(&relocInfo, 0, sizeof(BNRelocationInfo));
				if (m_objectFile)
				{
					// In unlinked images reloc.offset is relative to the info section specified
					if (reloc.sectionIdx >= m_elfSections.size())
						throw ReadException();
					auto sectionName = ReadStringTable(reader, m_sectionStringTable, m_elfSections[reloc.sectionIdx].name);
					auto sec = GetSectionByName(sectionName);
					if (!sec)
						continue;
					reloc.offset += sec->GetStart() - imageBaseAdjustment;
				}

				relocInfo.symbolIndex = reloc.sym;
				relocInfo.address = reloc.offset;
				relocInfo.nativeType = reloc.relocType;
				relocInfo.addend = reloc.addend;
				relocInfo.implicitAddend = reloc.implicit;
				relocInfo.base = baseAddress;
				virtualReader.Seek(relocInfo.address);
				memset(relocInfo.relocationDataCache, 0, sizeof(relocInfo.relocationDataCache));
				virtualReader.TryRead(relocInfo.relocationDataCache, MAX_RELOCATION_SIZE);
				m_relocationInfo.push_back(relocInfo);

				if (isArmV7)
				{
					if(reloc.relocType == R_ARM_TLS_DTPOFF32)
						tlsOffsets.push_back(reloc.offset);
					else if(reloc.relocType == R_ARM_TLS_DTPMOD32)
						tlsModuleStarts.push_back(reloc.offset);
				}
			}

			if (relocHandler->GetRelocationInfo(this, m_arch, m_relocationInfo))
			{
				vector<ElfSymbolTableEntry>* symTable = &symbolTable;
				if (!m_objectFile)
					symTable = &dynamicSymbolTable;

				size_t anonymousEntryCount = 0;
				for (auto& relocInfo : m_relocationInfo)
				{
					if (relocInfo.type == IgnoredRelocation)
						continue;

					// Define absolute relocations with no symbol specified such as R_PPC_RELATIVE and R_ARM_IRELATIVE
					// Define unhandled relocations in order to detect them and avoid creating functions at invalid target addresses
					if ((relocInfo.symbolIndex == 0) || (relocInfo.type == UnhandledRelocation))
					{
						relocInfo.baseRelative = imageBaseAdjustment != 0;
						DefineRelocation(m_arch, relocInfo, imageBaseAdjustment, relocInfo.address);
					}
					else
					{
						ElfSymbolTableEntry entry;
						if (relocInfo.symbolIndex < symTable->size())
							entry = (*symTable)[relocInfo.symbolIndex];
						else if (!ParseSymbolTableEntry(virtualReader, entry, relocInfo.symbolIndex, m_auxSymbolTable, m_dynamicStringTable, true))
							continue;

						if (relocInfo.type == ELFGlobalRelocationType)
							DefineElfSymbol(ImportAddressSymbol, entry.name, relocInfo.address, true, entry.binding, entry.size);
						else if (relocInfo.type == ELFCopyRelocationType)
							DefineElfSymbol(ImportedDataSymbol, entry.name, relocInfo.address, false, entry.binding, entry.size);
						else if (relocInfo.type == ELFJumpSlotRelocationType)
							DefineElfSymbol(ImportAddressSymbol, entry.name, relocInfo.address, true, entry.binding, entry.size);

						if (entry.type == ELF_STT_SECTION)
						{
							// Section relative relocation
							if (auto section = GetSectionByName(entry.name); section)
							{
								DefineRelocation(m_arch, relocInfo, section->GetStart(), relocInfo.address);
								continue;
							}
						}
						else if (!entry.section)
						{
							// handle anonymous symbol generation
							if (!entry.name.size())
							{
								entry.name = "anonymous_";
								if (entry.type == ELF_STT_FUNC)
									entry.name += "func";
								else if (entry.type == ELF_STT_OBJECT)
									entry.name += "object";
								else
									entry.name += "data";
								entry.name += "_";

								switch(entry.binding)
								{
									case NoBinding:
										entry.name += "bind_none";
										break;
									case LocalBinding:
										entry.name += "bind_local";
										break;
									case GlobalBinding:
										entry.name += "bind_global";
										break;
									case WeakBinding:
										entry.name += "bind_weak";
										break;
									default:
										break;
								}
								entry.name += "_";
								entry.name += std::to_string(anonymousEntryCount++);
								DefineElfSymbol(ExternalSymbol, entry.name, 0, false, entry.binding, entry.size);
							}

							// section undefined so query for external symbol directly
							auto symbol = GetSymbolByRawName(entry.name, GetExternalNameSpace());
							if (symbol)
							{
								DefineRelocation(m_arch, relocInfo, symbol, relocInfo.address);
								continue;
							}
						}
						else if (entry.section < m_elfSections.size())
						{
							// symbol is relative to a section, look up by address instead of name to avoid ambiguity
							uint64_t target = m_elfSections[entry.section].address + entry.value;
							auto symbol = GetSymbolByAddress(target);
							if (symbol)
							{
								DefineRelocation(m_arch, relocInfo, symbol, relocInfo.address);
								continue;
							}
						}

						// retrieve first symbol that is not a symbol relocation
						auto symbols = GetSymbolsByName(entry.name);
						for (const auto& symbol : symbols)
						{
							if (symbol->GetAddress() == relocInfo.address)
								continue;
							DefineRelocation(m_arch, relocInfo, symbol, relocInfo.address);
							break;
						}
					}
				}
			}
		}
		catch (ReadException&)
		{
			// Skip errors in relocation tables
			m_logger->LogError("Failed to parse relocations");
		}
	}

	// Add additional function starts, after symbols have been processed
	for (const auto& section : GetSections())
	{
		if ((section->GetLength() > 0) && ((section->GetName() == ".init") || (section->GetName() == ".fini")))
		{
			string autoSectionName = section->GetName();
			autoSectionName.replace(0, 1, "_");
			auto funcs = GetAnalysisFunctionsForAddress(section->GetStart());

			if (!m_backedByDatabase) // Don't create symbols that are present in the database snapshot now
			{
				auto symbol = GetSymbolByAddress(section->GetStart());
				if (!symbol)
					DefineAutoSymbol(new Symbol(FunctionSymbol, autoSectionName, section->GetStart(), GlobalBinding));
			}

			// Prefer function creation via recursive descent when encountering mixed architecture binaries where the entry point arch differs from the file arch
			if ((funcs.size() == 0) && (entryPointArch == m_arch))
			{
				AddFunctionForAnalysis(GetDefaultPlatform(), section->GetStart());
				m_logger->LogDebug("Adding function start: %#" PRIx64 "\n", section->GetStart());
			}
		}
		else if (!(section->GetLength() % m_addressSize) &&
			((section->GetName() == ".init_array") || (section->GetName() == ".fini_array") ||
				(section->GetName() == ".ctors") || (section->GetName() == ".dtors")))
		{
			// define a function pointer array: void (*init_array[])(void)
			auto function = Type::FunctionType(Type::VoidType(), platform->GetDefaultCallingConvention(), vector<FunctionParameter>())->WithConfidence(0);
			auto function_pointer = Type::PointerType(m_addressSize, function)->WithConfidence(0);
			auto array = Type::ArrayType(function_pointer, section->GetLength() / m_addressSize);
			DefineDataVariable(section->GetStart(), array);
			// trim the first '.' from the section name
			string autoSectionName = section->GetName().substr(1);
			// define a symbol for the array
			if (auto symbol = GetSymbolByAddress(section->GetStart()); !symbol)
				DefineAutoSymbol(new Symbol(DataSymbol, autoSectionName, section->GetStart(), NoBinding));

			virtualReader.Seek(section->GetStart());
			uint64_t maxAddress = -1;
			if (GetAddressSize() < 8)
				maxAddress = (1ULL << (8 * GetAddressSize())) - 1;

			for (uint32_t i = 0; i < section->GetLength() / m_addressSize; i++)
			{
				uint64_t entry;
				try
				{
					entry = virtualReader.ReadPointer();
					// ctor and dtor sections often contain address 0x0 and 0xffffffff as markers, we need to ignore
					// them
					if ((entry == 0) || (entry == maxAddress))
						continue;
				}
				catch (const ReadException& r)
				{
					m_logger->LogWarn("Fail to read pointer at %#" PRIx64 " while parsing section %s",
									  virtualReader.GetOffset(), autoSectionName.c_str());
					break;
				}

				if (entry)
				{
					entry += imageBaseAdjustment;
					Ref<Architecture> entryArch = entryPointArch->GetAssociatedArchitectureByAddress(entry);
					if (entryArch != entryPointArch)
					{
						auto func = AddFunctionForAnalysis(platform->GetRelatedPlatform(entryArch), entry);
						if (func)
						{
							AddToEntryFunctions(func);
						}
					}
					else
					{
						auto func = AddFunctionForAnalysis(platform, entry);
						if (func)
						{
							AddToEntryFunctions(func);
						}
					}
					m_logger->LogDebug("Adding function start: %#" PRIx64 "\n", entry);

					// name functions in .init_array, .fini_array, .ctors and .dtors
					if (!GetSymbolByAddress(entry))
					{
						if (section->GetName() == ".init_array")
							DefineElfSymbol(FunctionSymbol, "_INIT_" + std::to_string(i), entry, false, GlobalBinding);
						else if (section->GetName() == ".fini_array")
							DefineElfSymbol(FunctionSymbol, "_FINI_" + std::to_string(i), entry, false, GlobalBinding);
						else if (section->GetName() == ".ctors")
							DefineElfSymbol(FunctionSymbol, "_CTOR_" + std::to_string(i), entry, false, GlobalBinding);
						else if (section->GetName() == ".dtors")
							DefineElfSymbol(FunctionSymbol, "_DTOR_" + std::to_string(i), entry, false, GlobalBinding);
					}
				}
			}

		}
	}

	if (m_gotEntryLocations.size() > 0)
	{
		Ref<Section> got = GetSectionByName(".got");
		if (!got)
		{
			m_logger->LogWarn(
				"ELF view did not find a .got section despite detected relocations; "
				"attempting to create sections with appropriate semantics");

			// Ensure the collected GOT entry locations include the program header specified GOT address.
			if (gotStart)
			{
				m_gotEntryLocations.emplace(gotStart);
				// A common setup observed is GOT[0] being the resolver, GOT[1] a constant, then pointers.
				// If gotStart and a collected address sandwich a constant, include the constant.
				if (m_gotEntryLocations.find(gotStart + 2 * m_addressSize) != m_gotEntryLocations.end())
					m_gotEntryLocations.emplace(gotStart + m_addressSize);
			}

			map<uint64_t, size_t> gotSectionsToCreate;

			auto it = m_gotEntryLocations.begin();
			uint64_t start = *it;
			uint64_t next = start + m_addressSize;
			it++;

			while (true)
			{
				bool end = (it == m_gotEntryLocations.end());

				if (end || (*it != next))
				{
					gotSectionsToCreate[start] = next - start;

					if (end)
						break;

					start = *it;
					next = start;
				}

				next += m_addressSize;
				it++;
			}

			for (auto& s : gotSectionsToCreate)
			{
				// Don't try creating a section if it starts in an already-created
				// section.
				if (GetSectionsAt(s.first).size() > 0)
					continue;

				stringstream ss;
				ss << ".got_recovered_" << std::hex << s.first;
				AddAutoSection(ss.str(), s.first, s.second, ReadOnlyDataSectionSemantics);
			}
		}
	}

	// Sometimes ELF will specify Thumb entry points w/o the bottom bit set
	// To deal with this we delay adding entry points until after symbols have been resolved
	// and ALL the functions have been created. This allows us to query the existing functions
	// platform. All in an effort to not create a function with the wrong architecture
	if (entryPointAddress && (entryPointAddress != GetStart()))
	{
		auto func = GetAnalysisFunctionsForAddress(entryPointAddress);
		if (func.size() == 1)
			AddEntryPointForAnalysis(func[0]->GetPlatform(), entryPointAddress);
		else
			AddEntryPointForAnalysis(GetDefaultPlatform(), entryPointAddress);
	}

	// Add a symbol for the entry point
	if (entryPointAddress && (entryPointAddress != GetStart()) && !GetSymbolByAddress(entryPointAddress))
		DefineAutoSymbol(new Symbol(FunctionSymbol, "_start", entryPointAddress, GlobalBinding));

	// Create type for ELF identification
	const string structNamePrefix = (m_addressSize == 4) ? "Elf32_" : "Elf64_";

	StructureBuilder identBuilder;
	identBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 4), "signature");
	identBuilder.AddMember(Type::IntegerType(1, false), "file_class");
	identBuilder.AddMember(Type::IntegerType(1, false), "encoding");
	identBuilder.AddMember(Type::IntegerType(1, false), "version");
	identBuilder.AddMember(Type::IntegerType(1, false), "os");
	identBuilder.AddMember(Type::IntegerType(1, false), "abi_version");
	identBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 7), "pad");
	Ref<Structure> identStruct = identBuilder.Finalize();
	Ref<Type> identType = Type::StructureType(identStruct);
	QualifiedName identStructName = structNamePrefix + "Ident";
	const string identStructTypeId = Type::GenerateAutoTypeId("elf", identStructName);
	QualifiedName elfIdentStructName = DefineType(identStructTypeId, identStructName, identType);
	QualifiedName rawIdentStructName = GetParentView()->DefineType(identStructTypeId, identStructName, identType);

	// Create enum for ELF header machine
	EnumerationBuilder elfHeaderMachineBuilder;
	elfHeaderMachineBuilder.AddMemberWithValue("EM_NONE", EM_NONE);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_M32", EM_M32);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_SPARC", EM_SPARC);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_386", EM_386);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_68K", EM_68K);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_88K", EM_88K);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_860", EM_860);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_MIPS", EM_MIPS);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_S370", EM_S370);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_MIPS_RS3_LE", EM_MIPS_RS3_LE);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_PARISC", EM_PARISC);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_VPP500", EM_VPP500);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_SPARC32PLUS", EM_SPARC32PLUS);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_960", EM_960);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_PPC", EM_PPC);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_PPC64", EM_PPC64);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_S390", EM_S390);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_V800", EM_V800);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_FR20", EM_FR20);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_RH32", EM_RH32);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_RCE", EM_RCE);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_ARM", EM_ARM);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_FAKE_ALPHA", EM_FAKE_ALPHA);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_SH", EM_SH);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_SPARCV9", EM_SPARCV9);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_TRICORE", EM_TRICORE);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_ARC", EM_ARC);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_H8_300", EM_H8_300);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_H8_300H", EM_H8_300H);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_H8S", EM_H8S);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_H8_500", EM_H8_500);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_IA_64", EM_IA_64);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_MIPS_X", EM_MIPS_X);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_COLDFIRE", EM_COLDFIRE);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_68HC12", EM_68HC12);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_MMA", EM_MMA);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_PCP", EM_PCP);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_NCPU", EM_NCPU);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_NDR1", EM_NDR1);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_STARCORE", EM_STARCORE);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_ME16", EM_ME16);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_ST100", EM_ST100);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_TINYJ", EM_TINYJ);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_X86_64", EM_X86_64);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_PDSP", EM_PDSP);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_FX66", EM_FX66);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_ST9PLUS", EM_ST9PLUS);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_ST7", EM_ST7);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_68HC16", EM_68HC16);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_68HC11", EM_68HC11);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_68HC08", EM_68HC08);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_68HC05", EM_68HC05);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_SVX", EM_SVX);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_ST19", EM_ST19);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_VAX", EM_VAX);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_CRIS", EM_CRIS);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_JAVELIN", EM_JAVELIN);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_FIREPATH", EM_FIREPATH);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_ZSP", EM_ZSP);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_MMIX", EM_MMIX);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_HUANY", EM_HUANY);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_PRISM", EM_PRISM);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_AVR", EM_AVR);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_FR30", EM_FR30);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_D10V", EM_D10V);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_D30V", EM_D30V);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_V850", EM_V850);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_M32R", EM_M32R);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_MN10300", EM_MN10300);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_MN10200", EM_MN10200);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_PJ", EM_PJ);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_OPENRISC", EM_OPENRISC);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_ARC_A5", EM_ARC_A5);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_XTENSA", EM_XTENSA);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_ALTERA_NIOS2", EM_ALTERA_NIOS2);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_AARCH64", EM_AARCH64);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_TILEPRO", EM_TILEPRO);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_MICROBLAZE", EM_MICROBLAZE);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_TILEGX", EM_TILEGX);
	elfHeaderMachineBuilder.AddMemberWithValue("EM_NUM", EM_NUM);

	Ref<Enumeration> elfHeaderMachineEnum = elfHeaderMachineBuilder.Finalize();
	Ref<Type> elfHeaderMachineEnumType = Type::EnumerationType(GetParentView()->GetDefaultArchitecture(), elfHeaderMachineEnum, 2, false);
	const string elfHeaderMachineEnumName = "e_machine";
	const string elfHeaderMachineEnumId = Type::GenerateAutoTypeId("elf", elfHeaderMachineEnumName);
	QualifiedName elfElfHeaderMachineEnumName = DefineType(elfHeaderMachineEnumId, elfHeaderMachineEnumName, elfHeaderMachineEnumType);
	QualifiedName rawElfHeaderMachineEnumName = GetParentView()->DefineType(elfHeaderMachineEnumId, elfHeaderMachineEnumName, elfHeaderMachineEnumType);

	// Create enum for ELF header type
	EnumerationBuilder elfHeaderTypeBuilder;
	elfHeaderTypeBuilder.AddMemberWithValue("ET_NONE", ET_NONE);
	elfHeaderTypeBuilder.AddMemberWithValue("ET_REL", ET_REL);
	elfHeaderTypeBuilder.AddMemberWithValue("ET_EXEC", ET_EXEC);
	elfHeaderTypeBuilder.AddMemberWithValue("ET_DYN", ET_DYN);
	elfHeaderTypeBuilder.AddMemberWithValue("ET_CORE", ET_CORE);
	elfHeaderTypeBuilder.AddMemberWithValue("ET_NUM", ET_NUM);

	Ref<Enumeration> elfHeaderTypeEnum = elfHeaderTypeBuilder.Finalize();
	Ref<Type> elfHeaderTypeEnumType = Type::EnumerationType(GetParentView()->GetDefaultArchitecture(), elfHeaderTypeEnum, 2, false);
	const string elfHeaderTypeEnumName = "e_type";
	const string elfHeaderTypeEnumId = Type::GenerateAutoTypeId("elf", elfHeaderTypeEnumName);
	QualifiedName elfElfHeaderTypeEnumName = DefineType(elfHeaderTypeEnumId, elfHeaderTypeEnumName, elfHeaderTypeEnumType);
	QualifiedName rawElfHeaderTypeEnumName = GetParentView()->DefineType(elfHeaderTypeEnumId, elfHeaderTypeEnumName, elfHeaderTypeEnumType);

	// Create type for ELF header
	StructureBuilder elfHeaderBuilder;
	elfHeaderBuilder.AddMember(Type::NamedType(this, elfIdentStructName), "ident");
	elfHeaderBuilder.AddMember(Type::NamedType(this, elfElfHeaderTypeEnumName), "type");
	elfHeaderBuilder.AddMember(Type::NamedType(this, elfElfHeaderMachineEnumName), "machine");
	elfHeaderBuilder.AddMember(Type::IntegerType(4, false), "version");

	if (platform)
	{
		elfHeaderBuilder.AddMember(Type::PointerType(m_addressSize, Type::FunctionType(Type::VoidType(),
			platform->GetDefaultCallingConvention(), vector<FunctionParameter>())), "entry");
	}
	else
	{
		elfHeaderBuilder.AddMember(Type::PointerType(m_addressSize, Type::VoidType()), "entry");
	}

	elfHeaderBuilder.AddMember(Type::IntegerType(m_addressSize, false), "program_header_offset");
	elfHeaderBuilder.AddMember(Type::IntegerType(m_addressSize, false), "section_header_offset");
	elfHeaderBuilder.AddMember(Type::IntegerType(4, false), "flags");
	elfHeaderBuilder.AddMember(Type::IntegerType(2, false), "header_size");
	elfHeaderBuilder.AddMember(Type::IntegerType(2, false), "program_header_size");
	elfHeaderBuilder.AddMember(Type::IntegerType(2, false), "program_header_count");
	elfHeaderBuilder.AddMember(Type::IntegerType(2, false), "section_header_size");
	elfHeaderBuilder.AddMember(Type::IntegerType(2, false), "section_header_count");
	elfHeaderBuilder.AddMember(Type::IntegerType(2, false), "string_table");
	Ref<Structure> elfHeaderStruct = elfHeaderBuilder.Finalize();
	Ref<Type> elfHeaderType = Type::StructureType(elfHeaderStruct);
	QualifiedName headerName = structNamePrefix + "Header";
	const string headerTypeId = Type::GenerateAutoTypeId("elf", headerName);
	QualifiedName elfHeaderName = DefineType(headerTypeId, headerName, elfHeaderType);

	elfHeaderBuilder.ReplaceMember(0, Type::NamedType(GetParentView(), rawIdentStructName), "ident");
	elfHeaderBuilder.ReplaceMember(1, Type::NamedType(GetParentView(), rawElfHeaderTypeEnumName), "type");
	elfHeaderBuilder.ReplaceMember(2, Type::NamedType(GetParentView(), rawElfHeaderMachineEnumName), "machine");
	elfHeaderBuilder.ReplaceMember(4, Type::IntegerType(m_addressSize, false), "entry");
	Ref<Structure> rawElfHeaderStruct = elfHeaderBuilder.Finalize();
	Ref<Type> rawElfHeaderType = Type::StructureType(rawElfHeaderStruct);
	QualifiedName rawHeaderName = GetParentView()->DefineType(headerTypeId, headerName, rawElfHeaderType);

	// Define variable for ELF header
	uint64_t addr;
	if (GetAddressForDataOffset(0, addr))
	{
		DefineDataVariable(addr, Type::NamedType(this, elfHeaderName));
		DefineAutoSymbol(new Symbol(DataSymbol, "__elf_header", addr, LocalBinding));
	}
	GetParentView()->DefineDataVariable(0, Type::NamedType(GetParentView(), rawHeaderName));
	GetParentView()->DefineAutoSymbol(new Symbol(DataSymbol, "__elf_header", 0, LocalBinding));


	// Create enum for ELF program header type
	EnumerationBuilder programHeaderTypeBuilder;
	programHeaderTypeBuilder.AddMemberWithValue("PT_NULL", ELF_PT_NULL);
	programHeaderTypeBuilder.AddMemberWithValue("PT_LOAD", ELF_PT_LOAD);
	programHeaderTypeBuilder.AddMemberWithValue("PT_DYNAMIC", ELF_PT_DYNAMIC);
	programHeaderTypeBuilder.AddMemberWithValue("PT_INTERP", ELF_PT_INTERP);
	programHeaderTypeBuilder.AddMemberWithValue("PT_NOTE", ELF_PT_NOTE);
	programHeaderTypeBuilder.AddMemberWithValue("PT_SHLIB", ELF_PT_SHLIB);
	programHeaderTypeBuilder.AddMemberWithValue("PT_PHDR", ELF_PT_PHDR);
	programHeaderTypeBuilder.AddMemberWithValue("PT_TLS", ELF_PT_TLS);
	programHeaderTypeBuilder.AddMemberWithValue("PT_NUM", ELF_PT_NUM);
	programHeaderTypeBuilder.AddMemberWithValue("PT_LOOS", ELF_PT_LOOS);
	programHeaderTypeBuilder.AddMemberWithValue("PT_GNU_EH_FRAME", ELF_PT_GNU_EH_FRAME);
	programHeaderTypeBuilder.AddMemberWithValue("PT_GNU_STACK", ELF_PT_GNU_STACK);
	programHeaderTypeBuilder.AddMemberWithValue("PT_GNU_RELRO", ELF_PT_GNU_RELRO);
	programHeaderTypeBuilder.AddMemberWithValue("PT_GNU_PROPERTY", ELF_PT_GNU_PROPERTY);
	programHeaderTypeBuilder.AddMemberWithValue("PT_LOSUNW", ELF_PT_LOSUNW);
	programHeaderTypeBuilder.AddMemberWithValue("PT_SUNWBSS", ELF_PT_SUNWBSS);
	programHeaderTypeBuilder.AddMemberWithValue("PT_SUNWSTACK", ELF_PT_SUNWSTACK);
	programHeaderTypeBuilder.AddMemberWithValue("PT_MIPS_REGINFO", ELF_PT_MIPS_REGINFO);
	programHeaderTypeBuilder.AddMemberWithValue("PT_MIPS_RTPROC", ELF_PT_MIPS_RTPROC);
	programHeaderTypeBuilder.AddMemberWithValue("PT_MIPS_OPTIONS", ELF_PT_MIPS_OPTIONS);
	programHeaderTypeBuilder.AddMemberWithValue("PT_MIPS_ABIFLAGS", ELF_PT_MIPS_ABIFLAGS);

	Ref<Enumeration> programHeaderTypeEnum = programHeaderTypeBuilder.Finalize();
	Ref<Type> programHeaderTypeEnumType = Type::EnumerationType(GetParentView()->GetDefaultArchitecture(), programHeaderTypeEnum, 4, false);
	const string programHeaderTypeEnumName = "p_type";
	const string programHeaderTypeEnumId = Type::GenerateAutoTypeId("elf", programHeaderTypeEnumName);
	QualifiedName elfProgramHeaderTypeEnumName = DefineType(programHeaderTypeEnumId, programHeaderTypeEnumName, programHeaderTypeEnumType);
	QualifiedName rawProgramHeaderTypeEnumName = GetParentView()->DefineType(programHeaderTypeEnumId, programHeaderTypeEnumName, programHeaderTypeEnumType);


	// Create enum for ELF program header flags
	EnumerationBuilder programHeaderFlagsBuilder;
	programHeaderFlagsBuilder.AddMemberWithValue("PF_X", PF_X);
	programHeaderFlagsBuilder.AddMemberWithValue("PF_W", PF_W);
	programHeaderFlagsBuilder.AddMemberWithValue("PF_R", PF_R);

	Ref<Enumeration> programHeaderFlagsEnum = programHeaderFlagsBuilder.Finalize();
	Ref<Type> programHeaderFlagsEnumType = Type::EnumerationType(GetParentView()->GetDefaultArchitecture(), programHeaderFlagsEnum, 4, false);
	const string programHeaderFlagsEnumName = "p_flags";
	const string programHeaderFlagsEnumId = Type::GenerateAutoTypeId("elf", programHeaderFlagsEnumName);
	QualifiedName elfProgramHeaderFlagsEnumName = DefineType(programHeaderFlagsEnumId, programHeaderFlagsEnumName, programHeaderFlagsEnumType);
	QualifiedName rawProgramHeaderFlagsEnumName = GetParentView()->DefineType(programHeaderFlagsEnumId, programHeaderFlagsEnumName, programHeaderFlagsEnumType);

	// Create type for ELF program headers
	StructureBuilder programHeaderBuilder;
	if (m_addressSize == 4)
	{
		programHeaderBuilder.AddMember(Type::NamedType(this, elfProgramHeaderTypeEnumName), "type");
		programHeaderBuilder.AddMember(Type::IntegerType(4, false), "offset");
		programHeaderBuilder.AddMember(Type::IntegerType(4, false), "virtual_address");
		programHeaderBuilder.AddMember(Type::IntegerType(4, false), "physical_address");
		programHeaderBuilder.AddMember(Type::IntegerType(4, false), "file_size");
		programHeaderBuilder.AddMember(Type::IntegerType(4, false), "memory_size");
		programHeaderBuilder.AddMember(Type::NamedType(this, elfProgramHeaderFlagsEnumName), "flags");
		programHeaderBuilder.AddMember(Type::IntegerType(4, false), "align");
	}
	else
	{
		programHeaderBuilder.AddMember(Type::NamedType(this, elfProgramHeaderTypeEnumName), "type");
		programHeaderBuilder.AddMember(Type::NamedType(this, elfProgramHeaderFlagsEnumName), "flags");
		programHeaderBuilder.AddMember(Type::IntegerType(8, false), "offset");
		programHeaderBuilder.AddMember(Type::IntegerType(8, false), "virtual_address");
		programHeaderBuilder.AddMember(Type::IntegerType(8, false), "physical_address");
		programHeaderBuilder.AddMember(Type::IntegerType(8, false), "file_size");
		programHeaderBuilder.AddMember(Type::IntegerType(8, false), "memory_size");
		programHeaderBuilder.AddMember(Type::IntegerType(8, false), "align");
	}
	Ref<Structure> programHeaderStruct = programHeaderBuilder.Finalize();
	Ref<Type> programHeaderType = Type::StructureType(programHeaderStruct);
	QualifiedName programHeaderName = structNamePrefix + "ProgramHeader";
	const string programHeaderTypeId = Type::GenerateAutoTypeId("elf", programHeaderName);
	QualifiedName elfProgramHeaderName = DefineType(programHeaderTypeId, programHeaderName, programHeaderType);

	if (m_addressSize == 4)
	{
		programHeaderBuilder.ReplaceMember(0, Type::NamedType(GetParentView(), rawProgramHeaderTypeEnumName), "type");
		programHeaderBuilder.ReplaceMember(6, Type::NamedType(GetParentView(), rawProgramHeaderFlagsEnumName), "flags");
	}
	else
	{
		programHeaderBuilder.ReplaceMember(0, Type::NamedType(GetParentView(), rawProgramHeaderTypeEnumName), "type");
		programHeaderBuilder.ReplaceMember(1, Type::NamedType(GetParentView(), rawProgramHeaderFlagsEnumName), "flags");
	}
	Ref<Structure> rawProgramHeaderStruct = programHeaderBuilder.Finalize();
	Ref<Type> rawProgramHeaderType = Type::StructureType(rawProgramHeaderStruct);
	QualifiedName rawProgramHeaderName = GetParentView()->DefineType(programHeaderTypeId, programHeaderName, rawProgramHeaderType);

	// Define variable for ELF program headers
	if (m_programHeaderCount != 0)
	{
		if (GetAddressForDataOffset(m_programHeaderOffset, addr))
		{
			DefineDataVariable(addr, Type::ArrayType(Type::NamedType(this, elfProgramHeaderName),
				m_programHeaderCount));
			DefineAutoSymbol(new Symbol(DataSymbol, "__elf_program_headers", addr, LocalBinding));
		}
		GetParentView()->DefineDataVariable(m_programHeaderOffset, Type::ArrayType(Type::NamedType(
			GetParentView(), rawProgramHeaderName), m_programHeaderCount));
		GetParentView()->DefineAutoSymbol(new Symbol(DataSymbol, "__elf_program_headers", m_programHeaderOffset, LocalBinding));
	}

	// Create enum for ELF section header type
	EnumerationBuilder sectionHeaderTypeBuilder;
	sectionHeaderTypeBuilder.AddMemberWithValue("SHT_NULL", ELF_SHT_NULL);
	sectionHeaderTypeBuilder.AddMemberWithValue("SHT_PROGBITS", ELF_SHT_PROGBITS);
	sectionHeaderTypeBuilder.AddMemberWithValue("SHT_SYMTAB", ELF_SHT_SYMTAB);
	sectionHeaderTypeBuilder.AddMemberWithValue("SHT_STRTAB", ELF_SHT_STRTAB);
	sectionHeaderTypeBuilder.AddMemberWithValue("SHT_RELA", ELF_SHT_RELA);
	sectionHeaderTypeBuilder.AddMemberWithValue("SHT_HASH", ELF_SHT_HASH);
	sectionHeaderTypeBuilder.AddMemberWithValue("SHT_DYNAMIC", ELF_SHT_DYNAMIC);
	sectionHeaderTypeBuilder.AddMemberWithValue("SHT_NOTE", ELF_SHT_NOTE);
	sectionHeaderTypeBuilder.AddMemberWithValue("SHT_NOBITS", ELF_SHT_NOBITS);
	sectionHeaderTypeBuilder.AddMemberWithValue("SHT_REL", ELF_SHT_REL);
	sectionHeaderTypeBuilder.AddMemberWithValue("SHT_SHLIB", ELF_SHT_SHLIB);
	sectionHeaderTypeBuilder.AddMemberWithValue("SHT_DYNSYM", ELF_SHT_DYNSYM);
	sectionHeaderTypeBuilder.AddMemberWithValue("SHT_LOUSER", ELF_SHT_LOUSER);
	sectionHeaderTypeBuilder.AddMemberWithValue("SHT_HIUSER", ELF_SHT_HIUSER);

	// Machine specific section header types
	if (m_commonHeader.arch == EM_PARISC)
	{
		sectionHeaderTypeBuilder.AddMemberWithValue("SHT_PARISC_EXT", ELF_SHT_EXT);
		sectionHeaderTypeBuilder.AddMemberWithValue("SHT_PARISC_UNWIND", ELF_SHT_UNWIND);
		sectionHeaderTypeBuilder.AddMemberWithValue("SHT_PARISC_DOC", ELF_SHT_PARISC_DOC);
		sectionHeaderTypeBuilder.AddMemberWithValue("SHT_PARISC_ANNOT", ELF_SHT_PARISC_ANNOT);
	}
	else if (m_commonHeader.arch == EM_IA_64)
	{
		sectionHeaderTypeBuilder.AddMemberWithValue("SHT_IA_64_EXT", ELF_SHT_EXT);
		sectionHeaderTypeBuilder.AddMemberWithValue("SHT_IA_64_UNWIND", ELF_SHT_UNWIND);
		sectionHeaderTypeBuilder.AddMemberWithValue("SHT_IA_64_LOPSREG", ELF_SHT_IA_64_LOPSREG);
		sectionHeaderTypeBuilder.AddMemberWithValue("SHT_IA_64_HIPSREG", ELF_SHT_IA_64_HIPSREG);
		sectionHeaderTypeBuilder.AddMemberWithValue("SHT_IA_64_PRIORITY_INIT", ELF_SHT_IA_64_PRIORITY_INIT);
	}
	else if (m_commonHeader.arch == EM_X86_64)
	{
		sectionHeaderTypeBuilder.AddMemberWithValue("SHT_AMD64_UNWIND", ELF_SHT_UNWIND);
	}
	else
	{
		sectionHeaderTypeBuilder.AddMemberWithValue("SHT_LOPROC", ELF_SHT_LOPROC);
		sectionHeaderTypeBuilder.AddMemberWithValue("SHT_HIPROC", ELF_SHT_HIPROC);
	}

	Ref<Enumeration> sectionHeaderTypeEnum = sectionHeaderTypeBuilder.Finalize();
	Ref<Type> sectionHeaderTypeEnumType = Type::EnumerationType(GetParentView()->GetDefaultArchitecture(), sectionHeaderTypeEnum, 4, false);
	const string sectionHeaderTypeEnumName = "sh_type";
	const string sectionHeaderTypeEnumId = Type::GenerateAutoTypeId("elf", sectionHeaderTypeEnumName);
	QualifiedName elfSectionHeaderTypeEnumName = DefineType(sectionHeaderTypeEnumId, sectionHeaderTypeEnumName, sectionHeaderTypeEnumType);
	QualifiedName rawSectionHeaderTypeEnumName = GetParentView()->DefineType(sectionHeaderTypeEnumId, sectionHeaderTypeEnumName, sectionHeaderTypeEnumType);

	// Create enum for ELF section header flags
	EnumerationBuilder sectionHeaderFlagsBuilder;
	sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_WRITE", ELF_SHF_WRITE);
	sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_ALLOC", ELF_SHF_ALLOC);
	sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_EXECINSTR", ELF_SHF_EXECINSTR);
	sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_MERGE", ELF_SHF_MERGE);
	sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_STRINGS", ELF_SHF_STRINGS);
	sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_INFO_LINK", ELF_SHF_INFO_LINK);
	sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_LINK_ORDER", ELF_SHF_LINK_ORDER);
	sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_OS_NONCONFORMING", ELF_SHF_OS_NONCONFORMING);
	sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_GROUP", ELF_SHF_GROUP);
	sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_TLS", ELF_SHF_TLS);
	sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_COMPRESSED", ELF_SHF_COMPRESSED);
	sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_MASKOS", ELF_SHF_MASKOS);

	// Machine specific section header flags
	if (m_commonHeader.arch == EM_PARISC)
	{
		sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_PARISC_SHORT", ELF_SHF_PARISC_SHORT);
		sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_PARISC_HUGE", ELF_SHF_PARISC_HUGE);
		sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_PARISC_SBP", ELF_SHF_PARISC_SBP);
	}
	else if (m_commonHeader.arch == EM_IA_64)
	{
		sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_IA_64_SHORT", ELF_SHF_IA_64_SHORT);
		sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_IA_64_NORECOV", ELF_SHF_IA_64_NORECOV);
	}
	else if (m_commonHeader.arch == EM_X86_64)
	{
		sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_AMD64_LARGE", ELF_SHF_AMD64_LARGE);
	}
	else if (In(m_arch->GetName(), {"aarch64", "armv7", "armv7eb", "thumb2", "thumb2eb"}))
	{
		sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_ENTRYSECT", ELF_SHF_ENTRYSECT);
		sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_COMDEF", ELF_SHF_COMDEF);
	}
	else if (In(m_arch->GetName(), {"mipsel32", "mips32"}))
	{
		sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_MIPS_GPREL", ELF_SHF_MIPS_GPREL);
	}
	else if (In(m_arch->GetName(), {"ppc", "ppc64", "ppc_le", "ppc64_le"}))
	{
		sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_EXCLUDE", ELF_SHF_EXCLUDE);
	}
	else
	{
		sectionHeaderFlagsBuilder.AddMemberWithValue("SHF_MASKPROC", ELF_SHF_MASKPROC);
	}

	Ref<Enumeration> sectionHeaderFlagsEnum = sectionHeaderFlagsBuilder.Finalize();
	Ref<Type> sectionHeaderFlagsEnumType = Type::EnumerationType(GetParentView()->GetDefaultArchitecture(), sectionHeaderFlagsEnum, m_addressSize, false);
	const string sectionHeaderFlagsEnumName = "sh_flags";
	const string sectionHeaderFlagsEnumId = Type::GenerateAutoTypeId("elf", sectionHeaderFlagsEnumName);
	QualifiedName elfSectionHeaderFlagsEnumName = DefineType(sectionHeaderFlagsEnumId, sectionHeaderFlagsEnumName, sectionHeaderFlagsEnumType);
	QualifiedName rawSectionHeaderFlagsEnumName = GetParentView()->DefineType(sectionHeaderFlagsEnumId, sectionHeaderFlagsEnumName, sectionHeaderFlagsEnumType);

	// Create type for ELF section headers
	StructureBuilder sectionHeaderBuilder;
	sectionHeaderBuilder.AddMember(Type::IntegerType(4, false), "name");
	sectionHeaderBuilder.AddMember(Type::NamedType(this, elfSectionHeaderTypeEnumName), "type");
	sectionHeaderBuilder.AddMember(Type::NamedType(this, elfSectionHeaderFlagsEnumName), "flags");
	sectionHeaderBuilder.AddMember(Type::IntegerType(m_addressSize, false), "address");
	sectionHeaderBuilder.AddMember(Type::IntegerType(m_addressSize, false), "offset");
	sectionHeaderBuilder.AddMember(Type::IntegerType(m_addressSize, false), "size");
	sectionHeaderBuilder.AddMember(Type::IntegerType(4, false), "link");
	sectionHeaderBuilder.AddMember(Type::IntegerType(4, false), "info");
	sectionHeaderBuilder.AddMember(Type::IntegerType(m_addressSize, false), "align");
	sectionHeaderBuilder.AddMember(Type::IntegerType(m_addressSize, false), "entry_size");
	Ref<Structure> sectionHeaderStruct = sectionHeaderBuilder.Finalize();
	Ref<Type> sectionHeaderType = Type::StructureType(sectionHeaderStruct);
	QualifiedName sectionHeaderName = structNamePrefix + "SectionHeader";
	const string sectionHeaderTypeId = Type::GenerateAutoTypeId("elf", sectionHeaderName);
	QualifiedName elfSectionHeaderName = DefineType(sectionHeaderTypeId, sectionHeaderName, sectionHeaderType);

	sectionHeaderBuilder.ReplaceMember(1, Type::NamedType(GetParentView(), rawSectionHeaderTypeEnumName), "type");
	sectionHeaderBuilder.ReplaceMember(2, Type::NamedType(GetParentView(), rawSectionHeaderFlagsEnumName), "flags");
	Ref<Structure> rawSectionHeaderStruct = sectionHeaderBuilder.Finalize();
	Ref<Type> rawSectionHeaderType = Type::StructureType(rawSectionHeaderStruct);
	QualifiedName rawSectionHeaderName = GetParentView()->DefineType(sectionHeaderTypeId, sectionHeaderName, rawSectionHeaderType);

	// Define variable for ELF program headers
	if (m_sectionHeaderCount != 0)
	{
		uint64_t configuredSectionCount = 100;
		if (viewSettings && viewSettings->Contains("files.elf.maxSectionHeaderCount"))
			configuredSectionCount = viewSettings->Get<uint64_t>("files.elf.maxSectionHeaderCount", this);
		uint64_t sectionCount = std::min<uint64_t>(m_sectionHeaderCount, configuredSectionCount);
		if (GetAddressForDataOffset(m_sectionHeaderOffset, addr))
		{
			DefineDataVariable(addr, Type::ArrayType(Type::NamedType(this, elfSectionHeaderName), sectionCount));
			DefineAutoSymbol(new Symbol(DataSymbol, "__elf_section_headers", addr, LocalBinding));
		}
		GetParentView()->DefineDataVariable(m_sectionHeaderOffset, Type::ArrayType(Type::NamedType(GetParentView(), rawSectionHeaderName), sectionCount));
		GetParentView()->DefineAutoSymbol(new Symbol(DataSymbol, "__elf_section_headers", m_sectionHeaderOffset, LocalBinding));
	}

	// Add types for dynamic table
	if (m_dynamicTable.virtualAddress && m_numDynamicTableEntries)
	{
		EnumerationBuilder dynTagEnumBuilder;
		dynTagEnumBuilder.AddMemberWithValue("DT_NULL", ELF_DT_NULL);
		dynTagEnumBuilder.AddMemberWithValue("DT_NEEDED", ELF_DT_NEEDED);
		dynTagEnumBuilder.AddMemberWithValue("DT_PLTRELSZ", ELF_DT_PLTRELSZ);
		dynTagEnumBuilder.AddMemberWithValue("DT_PLTGOT", ELF_DT_PLTGOT);
		dynTagEnumBuilder.AddMemberWithValue("DT_HASH", ELF_DT_HASH);
		dynTagEnumBuilder.AddMemberWithValue("DT_STRTAB", ELF_DT_STRTAB);
		dynTagEnumBuilder.AddMemberWithValue("DT_SYMTAB", ELF_DT_SYMTAB);
		dynTagEnumBuilder.AddMemberWithValue("DT_RELA", ELF_DT_RELA);
		dynTagEnumBuilder.AddMemberWithValue("DT_RELASZ", ELF_DT_RELASZ);
		dynTagEnumBuilder.AddMemberWithValue("DT_RELAENT", ELF_DT_RELAENT);
		dynTagEnumBuilder.AddMemberWithValue("DT_STRSZ", ELF_DT_STRSZ);
		//dynTagEnumBuilder.AddMemberWithValue("DT_DYNSYM", ELF_DT_DYNSYM);
		dynTagEnumBuilder.AddMemberWithValue("DT_SYMENT", ELF_DT_SYMENT);
		dynTagEnumBuilder.AddMemberWithValue("DT_INIT", ELF_DT_INIT);
		dynTagEnumBuilder.AddMemberWithValue("DT_FINI", ELF_DT_FINI);
		dynTagEnumBuilder.AddMemberWithValue("DT_SONAME", ELF_DT_SONAME);
		dynTagEnumBuilder.AddMemberWithValue("DT_RPATH", ELF_DT_RPATH);
		dynTagEnumBuilder.AddMemberWithValue("DT_SYMBOLIC", ELF_DT_SYMBOLIC);
		dynTagEnumBuilder.AddMemberWithValue("DT_REL", ELF_DT_REL);
		dynTagEnumBuilder.AddMemberWithValue("DT_RELSZ", ELF_DT_RELSZ);
		dynTagEnumBuilder.AddMemberWithValue("DT_RELENT", ELF_DT_RELENT);
		dynTagEnumBuilder.AddMemberWithValue("DT_PLTREL", ELF_DT_PLTREL);
		dynTagEnumBuilder.AddMemberWithValue("DT_DEBUG", ELF_DT_DEBUG);
		dynTagEnumBuilder.AddMemberWithValue("DT_TEXTREL", ELF_DT_TEXTREL);
		dynTagEnumBuilder.AddMemberWithValue("DT_JMPREL", ELF_DT_JMPREL);
		dynTagEnumBuilder.AddMemberWithValue("DT_BIND_NOW", ELF_DT_BIND_NOW);
		dynTagEnumBuilder.AddMemberWithValue("DT_INIT_ARRAY", ELF_DT_INIT_ARRAY);
		dynTagEnumBuilder.AddMemberWithValue("DT_FINI_ARRAY", ELF_DT_FINI_ARRAY);
		dynTagEnumBuilder.AddMemberWithValue("DT_INIT_ARRAYSZ", ELF_DT_INIT_ARRAYSZ);
		dynTagEnumBuilder.AddMemberWithValue("DT_FINI_ARRAYSZ", ELF_DT_FINI_ARRAYSZ);
		dynTagEnumBuilder.AddMemberWithValue("DT_RUNPATH", ELF_DT_RUNPATH);
		dynTagEnumBuilder.AddMemberWithValue("DT_FLAGS", ELF_DT_FLAGS);
		dynTagEnumBuilder.AddMemberWithValue("DT_ENCODING", ELF_DT_ENCODING);
		dynTagEnumBuilder.AddMemberWithValue("DT_PREINIT_ARRAY", ELF_DT_PREINIT_ARRAY);
		dynTagEnumBuilder.AddMemberWithValue("DT_PREINIT_ARRAYSZ", ELF_DT_PREINIT_ARRAYSZ);

		dynTagEnumBuilder.AddMemberWithValue("DT_LOOS", ELF_DT_LOOS);
		dynTagEnumBuilder.AddMemberWithValue("DT_SUNW_RTLDINF", ELF_DT_SUNW_RTLDINF);
		dynTagEnumBuilder.AddMemberWithValue("DT_HIOS", ELF_DT_HIOS);
		dynTagEnumBuilder.AddMemberWithValue("DT_VALRNGLO", ELF_DT_VALRNGLO);
		dynTagEnumBuilder.AddMemberWithValue("DT_CHECKSUM", ELF_DT_CHECKSUM);
		dynTagEnumBuilder.AddMemberWithValue("DT_PLTPADSZ", ELF_DT_PLTPADSZ);
		dynTagEnumBuilder.AddMemberWithValue("DT_MOVEENT", ELF_DT_MOVEEN);
		dynTagEnumBuilder.AddMemberWithValue("DT_MOVESZ", ELF_DT_MOVES);
		dynTagEnumBuilder.AddMemberWithValue("DT_FEATURE_1", ELF_DT_FEATURE_1);
		dynTagEnumBuilder.AddMemberWithValue("DT_POSFLAG_1", ELF_DT_POSFLAG_1);
		dynTagEnumBuilder.AddMemberWithValue("DT_SYMINSZ", ELF_DT_SYMINSZ);
		dynTagEnumBuilder.AddMemberWithValue("DT_SYMINENT", ELF_DT_SYMINENT);
		dynTagEnumBuilder.AddMemberWithValue("DT_VALRNGHI", ELF_DT_VALRNGH);
		dynTagEnumBuilder.AddMemberWithValue("DT_ADDRRNGLO", ELF_DT_ADDRRNGLO);
		dynTagEnumBuilder.AddMemberWithValue("DT_GNU_HASH", ELF_DT_GNU_HASH);
		dynTagEnumBuilder.AddMemberWithValue("DT_CONFIG", ELF_DT_CONFIG);
		dynTagEnumBuilder.AddMemberWithValue("DT_DEPAUDIT", ELF_DT_DEPAUDIT);
		dynTagEnumBuilder.AddMemberWithValue("DT_AUDIT", ELF_DT_AUDIT);
		dynTagEnumBuilder.AddMemberWithValue("DT_PLTPAD", ELF_DT_PLTPAD);
		dynTagEnumBuilder.AddMemberWithValue("DT_MOVETAB", ELF_DT_MOVETAB);
		dynTagEnumBuilder.AddMemberWithValue("DT_SYMINFO", ELF_DT_SYMINFO);
		dynTagEnumBuilder.AddMemberWithValue("DT_ADDRRNGHI", ELF_DT_ADDRRNGHI);
		dynTagEnumBuilder.AddMemberWithValue("DT_RELACOUNT", ELF_DT_RELACOUNT);
		dynTagEnumBuilder.AddMemberWithValue("DT_RELCOUNT", ELF_DT_RELCOUNT);
		dynTagEnumBuilder.AddMemberWithValue("DT_FLAGS_1", ELF_DT_FLAGS_1);
		dynTagEnumBuilder.AddMemberWithValue("DT_VERDEF", ELF_DT_VERDEF);
		dynTagEnumBuilder.AddMemberWithValue("DT_VERDEFNUM", ELF_DT_VERDEFNUM);
		dynTagEnumBuilder.AddMemberWithValue("DT_VERNEED", ELF_DT_VERNEED);
		dynTagEnumBuilder.AddMemberWithValue("DT_VERNEEDNUM", ELF_DT_VERNEEDNUM);
		dynTagEnumBuilder.AddMemberWithValue("DT_VERSYM", ELF_DT_VERSYM);

		dynTagEnumBuilder.AddMemberWithValue("DT_MIPS_RLD_VERSION", ELF_DT_MIPS_RLD_VERSION);
		dynTagEnumBuilder.AddMemberWithValue("DT_MIPS_TIME_STAMP", ELF_DT_MIPS_TIME_STAMP);
		dynTagEnumBuilder.AddMemberWithValue("DT_MIPS_ICHECKSUM", ELF_DT_MIPS_ICHECKSUM);
		dynTagEnumBuilder.AddMemberWithValue("DT_MIPS_IVERSION", ELF_DT_MIPS_IVERSION);
		dynTagEnumBuilder.AddMemberWithValue("DT_MIPS_FLAGS", ELF_DT_MIPS_FLAGS);
		dynTagEnumBuilder.AddMemberWithValue("DT_MIPS_BASE_ADDRESS", ELF_DT_MIPS_BASE_ADDRESS);
		dynTagEnumBuilder.AddMemberWithValue("DT_MIPS_CONFLICT", ELF_DT_MIPS_CONFLICT);
		dynTagEnumBuilder.AddMemberWithValue("DT_MIPS_LIBLIST", ELF_DT_MIPS_LIBLIST);
		dynTagEnumBuilder.AddMemberWithValue("DT_MIPS_LOCAL_GOTNO", ELF_DT_MIPS_LOCAL_GOTNO);
		dynTagEnumBuilder.AddMemberWithValue("DT_MIPS_CONFLICTNO", ELF_DT_MIPS_CONFLICTNO);
		dynTagEnumBuilder.AddMemberWithValue("DT_MIPS_LIBLISTNO", ELF_DT_MIPS_LIBLISTNO);
		dynTagEnumBuilder.AddMemberWithValue("DT_MIPS_SYMTABNO", ELF_DT_MIPS_SYMTABNO);
		dynTagEnumBuilder.AddMemberWithValue("DT_MIPS_UNREFEXTNO", ELF_DT_MIPS_UNREFEXTNO);
		dynTagEnumBuilder.AddMemberWithValue("DT_MIPS_GOTSYM", ELF_DT_MIPS_GOTSYM);
		dynTagEnumBuilder.AddMemberWithValue("DT_MIPS_HIPAGENO", ELF_DT_MIPS_HIPAGENO);
		dynTagEnumBuilder.AddMemberWithValue("DT_MIPS_RLD_MAP", ELF_DT_MIPS_RLD_MAP);
		dynTagEnumBuilder.AddMemberWithValue("DT_MIPS_RLD_MAP_REL", ELF_DT_MIPS_RLD_MAP_REL);

		uint64_t entrySize = m_elf32 ? 8 : 16;
		Ref<Enumeration> dynTagEnum = dynTagEnumBuilder.Finalize();
		Ref<Type> dynTagEnumType = Type::EnumerationType(GetParentView()->GetDefaultArchitecture(), dynTagEnum, entrySize / 2, false);
		const string dynTagEnumName = "e_dyn_tag";
		const string dynTagEnumId = Type::GenerateAutoTypeId("elf", dynTagEnumName);
		QualifiedName elfdynTagEnumName = DefineType(dynTagEnumId, dynTagEnumName, dynTagEnumType);

		StructureBuilder dynamicEntryBuilder;
		dynamicEntryBuilder.AddMember(Type::NamedType(this, elfdynTagEnumName), "d_tag");
		dynamicEntryBuilder.AddMember(Type::IntegerType(entrySize / 2, false), "d_val");
		Ref<Structure> dynEntryStruct = dynamicEntryBuilder.Finalize();
		Ref<Type> dynEntryType = Type::StructureType(dynEntryStruct);
		QualifiedName dynEntryName = m_elf32 ? string("Elf32_Dyn"): string("Elf64_Dyn");
		const string dynEntryTypeId = Type::GenerateAutoTypeId("elf", dynEntryName);
		QualifiedName dynEntryTypeName = DefineType(dynEntryTypeId, dynEntryName, dynEntryType);
		uint64_t adjustedVirtualAddr = m_dynamicTable.virtualAddress + imageBaseAdjustment;
		DefineDataVariable(adjustedVirtualAddr, Type::ArrayType(Type::NamedType(this, dynEntryTypeName), m_numDynamicTableEntries));
		DefineAutoSymbol(new Symbol(DataSymbol, "__elf_dynamic_table", adjustedVirtualAddr, NoBinding));
	}

	if (m_auxSymbolTable.size || m_symbolTableSection.offset)
	{
		StructureBuilder symTableBuilder;
		if (m_elf32)
		{
			symTableBuilder.AddMember(Type::IntegerType(4, false), "st_name");
			symTableBuilder.AddMember(Type::IntegerType(4, false), "st_value");
			symTableBuilder.AddMember(Type::IntegerType(4, false), "st_size");
			symTableBuilder.AddMember(Type::IntegerType(1, false), "st_info");
			symTableBuilder.AddMember(Type::IntegerType(1, false), "st_other");
			symTableBuilder.AddMember(Type::IntegerType(2, false), "st_shndx");
		}
		else
		{
			symTableBuilder.AddMember(Type::IntegerType(4, false), "st_name");
			symTableBuilder.AddMember(Type::IntegerType(1, false), "st_info");
			symTableBuilder.AddMember(Type::IntegerType(1, false), "st_other");
			symTableBuilder.AddMember(Type::IntegerType(2, false), "st_shndx");
			symTableBuilder.AddMember(Type::IntegerType(8, false), "st_value");
			symTableBuilder.AddMember(Type::IntegerType(8, false), "st_size");
		}
		Ref<Structure> symTableStruct = symTableBuilder.Finalize();
		Ref<Type> symTableType = Type::StructureType(symTableStruct);
		QualifiedName symTableName = m_elf32 ? string("Elf32_Sym") : string("Elf64_Sym");
		const string symTableTypeId = Type::GenerateAutoTypeId("elf", symTableName);

		// Add types for the dynamic symbol table
		if (m_auxSymbolTable.size)
		{
			auto defineAuxSymTableForView = [&](Ref<BinaryView> view) {
				QualifiedName symTableTypeName = view->DefineType(symTableTypeId, symTableName, symTableType);
				view->DefineDataVariable(m_auxSymbolTable.offset, Type::ArrayType(Type::NamedType(this, symTableTypeName), m_auxSymbolTable.size / m_auxSymbolTableEntrySize));
				view->DefineAutoSymbol(new Symbol(DataSymbol, "__elf_symbol_table", m_auxSymbolTable.offset, NoBinding));
			};
			defineAuxSymTableForView(this);
			defineAuxSymTableForView(GetParentView());
		}

		if (m_symbolTableSection.offset)
		{
			QualifiedName symTableTypeName = GetParentView()->DefineType(symTableTypeId, symTableName, symTableType);
			GetParentView()->DefineDataVariable(m_symbolTableSection.offset, Type::ArrayType(Type::NamedType(this, symTableTypeName), m_symbolTableSection.size / m_auxSymbolTableEntrySize));
			GetParentView()->DefineAutoSymbol(new Symbol(DataSymbol, "__elf_symbol_table", m_symbolTableSection.offset, NoBinding));
		}
	}

	if (m_relocSection.size && m_relocSection.entrySize > 0)
	{
		StructureBuilder relocationTableBuilder;
		if (m_elf32)
		{
			relocationTableBuilder.AddMember(Type::IntegerType(4, false), "r_offset");
			relocationTableBuilder.AddMember(Type::IntegerType(4, false), "r_info");
		}
		else
		{
			relocationTableBuilder.AddMember(Type::IntegerType(8, false), "r_offset");
			relocationTableBuilder.AddMember(Type::IntegerType(8, false), "r_info");
		};
		Ref<Structure> relocationTableStruct = relocationTableBuilder.Finalize();
		Ref<Type> relocationTableType = Type::StructureType(relocationTableStruct);
		QualifiedName relocationTableName = m_elf32 ? string("Elf32_Rel") : string("Elf64_Rel");
		const string relocationTableTypeId = Type::GenerateAutoTypeId("elf", relocationTableName);

		QualifiedName relocTableTypeName = DefineType(relocationTableTypeId, relocationTableName, relocationTableType);
		DefineDataVariable(m_relocSection.offset,
			Type::ArrayType(Type::NamedType(this, relocTableTypeName), m_relocSection.size / m_relocSection.entrySize));
		DefineAutoSymbol(new Symbol(DataSymbol, "__elf_rel_table", m_relocSection.offset, NoBinding));
	}

	if (m_relocaSection.size && m_relocaSection.entrySize > 0)
	{
		StructureBuilder relocationATableBuilder;
		if (m_elf32)
		{
			relocationATableBuilder.AddMember(Type::IntegerType(4, false), "r_offset");
			relocationATableBuilder.AddMember(Type::IntegerType(4, false), "r_info");
			relocationATableBuilder.AddMember(Type::IntegerType(4, true), "r_addend");
		}
		else
		{
			relocationATableBuilder.AddMember(Type::IntegerType(8, false), "r_offset");
			relocationATableBuilder.AddMember(Type::IntegerType(8, false), "r_info");
			relocationATableBuilder.AddMember(Type::IntegerType(8, true), "r_addend");
		};
		Ref<Structure> relocationATableStruct = relocationATableBuilder.Finalize();
		Ref<Type> relocationATableType = Type::StructureType(relocationATableStruct);
		QualifiedName relocationATableName = m_elf32 ? string("Elf32_Rela") : string("Elf64_Rela");
		const string relocationATableTypeId = Type::GenerateAutoTypeId("elf", relocationATableName);

		QualifiedName relocaTableTypeName =
			DefineType(relocationATableTypeId, relocationATableName, relocationATableType);
		DefineDataVariable(m_relocaSection.offset,
			Type::ArrayType(
				Type::NamedType(this, relocaTableTypeName), m_relocaSection.size / m_relocaSection.entrySize));
		DefineAutoSymbol(new Symbol(DataSymbol, "__elf_rela_table", m_relocaSection.offset, NoBinding));
	}

	// In 32-bit mips with .got, add .extern symbol "RTL_Resolve"
	if (gotStart && In(m_arch->GetName(), {"mips32", "mipsel32", "mips64", "nanomips"}))
	{
		const char *name = "RTL_Resolve";

		/* create symbol for RTL_Resolve(), address will be auto-assigned after placement in .extern */
		Ref<Symbol> symbol = new Symbol(
			ExternalSymbol, /* type */
			name, /* shortName */
			name, /* fullName */
			name, /* rawName */
			0, /* byAddr */
			GlobalBinding, /* binding */
			GetExternalNameSpace() /* namespace */
		);

		/* create type, associate it with RTL_Resolve */
		Ref<Type> ptr_type = Type::PointerType(m_arch, Type::VoidType())->WithConfidence(BN_FULL_CONFIDENCE);

		Ref<CallingConvention> cc = m_arch->GetCallingConventionByName("linux-rtlresolve");

		Ref<Type> type = Type::FunctionType(
				Type::VoidType(), /* returnValue */
				cc, /* callingConvention */
				{ /* params */
					FunctionParameter("caller_ret_addr", ptr_type),
					FunctionParameter("sym_idx", Type::IntegerType(4, true)),
				},
				false, /* hasVariableArguments */
				false, /* canReturn */
				0
		);

		/* This BinaryView helper does:
		   1) DefineAutoSymbol(symbol);
		   2) m_externalTypes[name] = type;
		   ...so that upon BinaryView finalization, data variables are made. */
		DefineAutoSymbolAndVariableOrFunction(GetDefaultPlatform(), symbol, type);

		/* Create relocation entry associated with this symbol so that reloc
		   servicing will overwrite GOT[0] with symbol's address. */
		BNRelocationInfo relocInfo;
		memset(&relocInfo, 0, sizeof(BNRelocationInfo));
		relocInfo.base = gotStart;
		relocInfo.address = gotStart;
		relocInfo.size = m_arch->GetAddressSize();
		relocInfo.nativeType = m_arch->GetAddressSize() == 4 ? 2 /* R_MIPS_32 */ : 18 /* R_MIPS_64 */;

		DefineRelocation(m_arch, relocInfo, symbol, relocInfo.address);
	}

	// Add type, data variables for TLS entries
	for (auto offset : tlsModuleStarts)
	{
		/* All module ID's are set to 0. */
		DefineDataVariable(offset, Type::IntegerType(4, false)->WithConfidence(BN_FULL_CONFIDENCE));
	}
	for (auto offset : tlsOffsets)
	{
		/* In runtime reality, these become the offsets of the variables within TLS data structures.
		   In static listing, we place a pointer to the variable for user convenience. */
		DefineDataVariable(offset,
			Type::PointerType(m_arch, Type::VoidType()));
	}
	std::chrono::steady_clock::time_point endTime = std::chrono::steady_clock::now();
	double t = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count() / 1000.0;
	m_logger->LogInfo("ELF parsing took %.3f seconds\n", t);
	m_stringTableCache.clear();
	return true;
}


void ElfView::DefineElfSymbol(BNSymbolType type, const string& incomingName, uint64_t addr, bool gotEntry,
	BNSymbolBinding binding, size_t size, Ref<Type> typeObj)
{
	// Ensure symbol is within the executable
	if (type != ExternalSymbol && !IsValidOffset(addr))
		return;

	string name = incomingName;
	Ref<Type> symbolTypeRef;
	if ((type == ExternalSymbol) || (type == ImportAddressSymbol) || (type == ImportedDataSymbol))
	{
		QualifiedName n(name);
		Ref<TypeLibrary> lib = nullptr;
		symbolTypeRef = ImportTypeLibraryObject(lib, n);
		if (symbolTypeRef)
		{
			m_logger->LogDebug("elf: type Library '%s' found hit for '%s'", lib->GetName().c_str(), name.c_str());
			if (type != ExternalSymbol || addr != 0)
			{
				RecordImportedObjectLibrary(GetDefaultPlatform(), addr, lib, n);
			}
		}
	}

	auto pos = name.rfind("@@");
	if (type == ExternalSymbol && pos != string::npos)
	{
		name = name.substr(0, pos);
	}

	pos = name.rfind("@GLIBC");
	if (type == ExternalSymbol && pos != string::npos)
	{
		name = name.substr(0, pos);
	}

	pos = name.rfind("@CXXABI");
	if (type == ExternalSymbol && pos != string::npos)
	{
		name = name.substr(0, pos);
	}


	// Deprioritize local label symbol names
	if (type == DataSymbol && binding == LocalBinding && !name.empty() && name[0] == '.')
	{
		type = LocalLabelSymbol;
	}

	// If name is empty, symbol is not valid
	if (name.size() == 0)
		return;

	if (!symbolTypeRef)
		symbolTypeRef = typeObj;

	if (gotEntry)
		m_gotEntryLocations.emplace(addr);

	auto process = [=]() {
		NameSpace nameSpace = GetInternalNameSpace();
		if (type == ExternalSymbol)
		{
			nameSpace = GetExternalNameSpace();
		}

		// If name does not start with alphabetic character or symbol, prepend an underscore
		string rawName = name;
		if (!(((name[0] >= 'A') && (name[0] <= 'Z')) || ((name[0] >= 'a') && (name[0] <= 'z')) || (name[0] == '_')
				|| (name[0] == '?') || (name[0] == '$') || (name[0] == '@') || (name[0] == '.')))
			rawName = "_" + name;

		// Try to demangle any C++ symbols
		string shortName = rawName;
		string fullName = rawName;
		Ref<Type> typeRef = symbolTypeRef;
		if (m_arch)
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
				if (!typeRef && m_extractMangledTypes && !GetDefaultPlatform()->GetFunctionByName(rawName))
					typeRef = demangledType;
			}
		}

		if (!typeRef && (size > 0 && size <= 8))
		{
			typeRef = Type::IntegerType(size, false);
		}

		return std::pair<Ref<Symbol>, Ref<Type>>(
			new Symbol(type, shortName, fullName, rawName, addr, binding, nameSpace), typeRef);
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


void ElfView::ApplyTypesToParentStringTable(const Elf64SectionHeader& section, const bool offset)
{
	m_logger->LogInfo("Found string table of size %p at offset %p", section.size, section.offset);
	DataBuffer buffer = GetParentView()->ReadBuffer(section.offset, section.size);
	if (buffer.GetLength() != section.size)
		return;
	unordered_map<size_t, Ref<Type>> cachedTypes;
	for (size_t start_address = (offset ? 1 : 0); start_address < section.size; ++start_address)
	{
		size_t len;
		char ch = 0;
		for (len = 0; len < BN_MAX_STRING_LENGTH * 3 && start_address + len < section.size; ++len)
		{
			ch = buffer[start_address + len];
			if (ch == 0)
				break;
		}

		if (len != 0 && ch == 0)
		{
			auto i = cachedTypes.find(len);
			Ref<Type> type;
			if (i == cachedTypes.end())
			{
				type = Type::ArrayType(Type::IntegerType(1, true), len + 1);
				cachedTypes[len] = type;
			}
			else
			{
				type = i->second;
			}

			GetParentView()->DefineDataVariable(section.offset + start_address, type);
		}

		start_address += len;
	}
}


void ElfView::ApplyTypesToStringTable(const Elf64SectionHeader& section, const int64_t imageBaseAdjustment, const bool offset)
{
	m_logger->LogInfo("Found string table of size %p at address %p", section.size, section.address);
	DataVariable existing_var;
	unordered_map<uint64_t, Ref<Type>> cachedTypes;
	for (size_t start_address = section.offset + (offset ? 1 : 0); start_address < section.offset + section.size;)
	{
		if (!GetParentView()->GetDataVariableAtAddress(start_address, existing_var) || (existing_var.address != start_address))
			return;

		const uint64_t len = existing_var.type->GetElementCount();

		auto i = cachedTypes.find(len);
		Ref<Type> type;
		if (i == cachedTypes.end())
		{
			type = Type::ArrayType(Type::IntegerType(1, true), len);
			cachedTypes[len] = type;
		}
		else
		{
			type = i->second;
		}
		DefineDataVariable(start_address - section.offset + section.address + imageBaseAdjustment, type);

		start_address += len;
	}
}


string ElfView::ReadStringTable(BinaryReader& reader, const Elf64SectionHeader& section, uint64_t offset)
{
	if (offset == 0 || offset > section.size)
		return "";

	auto itr = m_stringTableCache.find(section.offset);
	if (itr == m_stringTableCache.end())
	{
		if (section.size > GetParentView()->GetLength())
		{
			m_logger->LogError("Unable to read string table with section offset: 0x%" PRIx64 " size: 0x%" PRIx64, section.offset, section.size);
			return "";
		}

		std::vector<char>& tableCache = m_stringTableCache[section.offset];
		tableCache.resize(section.size);
		reader.Seek(section.offset);
		reader.Read(tableCache.data(), section.size);
		itr = m_stringTableCache.find(section.offset);
	}

	const std::vector<char>& tableCache = itr->second;
	return std::string(&tableCache[offset], strlen(tableCache.data() + offset));
}


// http://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi-1.9.html#FUNC-DES
bool ElfView::DerefPpc64Descriptor(BinaryReader& reader, uint64_t addr, uint64_t& result)
{
	/* must be 64-bit ELF, arch PPC64 */
	if (m_elf32 || m_commonHeader.arch != EM_PPC64)
		return false;

	/* .opd section must exist */
	if (!m_sectionOpd.size)
		return false;

	/* addr must be within .opd section */
	if (addr < m_sectionOpd.address || addr >= m_sectionOpd.address + m_sectionOpd.size)
		return false;

	/* dereference descriptor to get function entry */
	uint64_t saved = reader.GetOffset();
	reader.Seek(m_sectionOpd.offset + (addr - m_sectionOpd.address));
	bool read_success = reader.TryRead64(result);;
	reader.Seek(saved);
	return read_success;
}


void ElfView::ParseMiniDebugInfo()
{
	Ref<Section> gnuDebugdata = GetParentView()->GetSectionByName(".gnu_debugdata");
	if (!gnuDebugdata)
		return;

	BinaryReader debugdataReader(GetParentView());
	debugdataReader.Seek(gnuDebugdata->GetStart());

	DataBuffer compressedDebug = debugdataReader.Read(gnuDebugdata->GetLength());

	DataBuffer debugElf;
	if (!compressedDebug.XzDecompress(debugElf))
	{
		m_logger->LogError("Invalid .gnu_debugdata contents: Failed to decompress");
		return;
	}

	Ref<BinaryView> debugBv = Load(debugElf, false);
	if (!debugBv)
	{
		m_logger->LogError("Invalid .gnu_debugdata contents: Failed to create BinaryView");
		return;
	}

	for (const auto& symbol : debugBv->GetSymbols())
	{
		DefineElfSymbol(
			symbol->GetType(),
			symbol->GetRawName(),
			GetStart() + symbol->GetAddress(),
			false,
			symbol->GetBinding()
		);
	}
}


vector<ElfSymbolTableEntry> ElfView::ParseSymbolTable(BinaryReader& reader, const Elf64SectionHeader& symbolSection,
	const Elf64SectionHeader& stringSection, bool dynamic, size_t startEntry)
{
	size_t size = (size_t)symbolSection.size / (m_elf32 ? 16 : 24);
	vector<ElfSymbolTableEntry> result;
	for (size_t i = startEntry; i < size; i++)
	{
		ElfSymbolTableEntry entry;
		if (!ParseSymbolTableEntry(reader, entry, i, symbolSection, stringSection, dynamic))
			break;

		/* TODO: PPC64 specific symbol handling to be moved to architecture extension for ELF */
		if (m_commonHeader.arch == EM_PPC64 && entry.type == ELF_STT_FUNC)
		{
			uint64_t func_start;
			if (DerefPpc64Descriptor(reader, entry.value, func_start))
			{
				if (entry.name[0] != '.')
				{
					/* new symbol with function entry as address */
					ElfSymbolTableEntry entry2 = entry;
					entry2.name = "." + entry2.name;
					entry2.value = func_start;
					result.push_back(entry2);

					m_logger->LogDebug("PPC64 symbol %s=%016x to %s=%016x\n", entry.name.c_str(), entry.value,
						entry2.name.c_str(), entry2.value);

					/* force the descriptor to a data symbol */
					entry.type = ELF_STT_OBJECT;
				}
			}
		}

		result.push_back(entry);
	}

	return result;
}


uint64_t ElfView::PerformGetEntryPoint() const
{
	return m_entryPoint;
}


BNEndianness ElfView::PerformGetDefaultEndianness() const
{
	return m_endian;
}


bool ElfView::PerformIsRelocatable() const
{
	return m_relocatable;
}


size_t ElfView::PerformGetAddressSize() const
{
	return m_addressSize;
}


ElfViewType::ElfViewType(): BinaryViewType("ELF", "ELF")
{
	m_logger = LogRegistry::CreateLogger("BinaryView.ElfViewType");
}


Ref<BinaryView> ElfViewType::Create(BinaryView* data)
{
	try
	{
		return new ElfView(data);
	}
	catch (std::exception& e)
	{
		m_logger->LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}


Ref<BinaryView> ElfViewType::Parse(BinaryView* data)
{
	try
	{
		return new ElfView(data, true);
	}
	catch (std::exception& e)
	{
		m_logger->LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}


bool ElfViewType::IsTypeValidForData(BinaryView* data)
{
	DataBuffer sig = data->ReadBuffer(0, 4);
	if (sig.GetLength() != 4)
		return false;
	if (memcmp(sig.GetData(), "\x7f" "ELF", 4) == 0)
		return true;

	// Cyber Grand Challenge DECREE executables can be parsed as ELF
	if (memcmp(sig.GetData(), "\x7f" "CGC", 4) == 0)
		return true;

	return false;
}


uint64_t ElfViewType::ParseHeaders(BinaryView* data, ElfIdent& ident, ElfCommonHeader& commonHeader, Elf64Header& header, Ref<Architecture>* arch, Ref<Platform>* plat, string& errorMsg, BNEndianness& endianness)
{
	if (!IsTypeValidForData(data))
	{
		errorMsg = "invalid signature";
		return 0;
	}

	// parse ElfIdent
	if (data->Read(&ident, 0, sizeof(ident)) != sizeof(ident))
	{
		errorMsg = "unable to read header";
		return 0;
	}

	BinaryReader reader(data);
	if (ident.encoding <= 1)
		endianness = LittleEndian;
	else if (ident.encoding == 2)
		endianness = BigEndian;
	else
	{
		errorMsg = "invalid encoding";
		return 0;
	}

	// parse ElfCommonHeader
	reader.SetEndianness(endianness);
	reader.Seek(sizeof(ident));
	commonHeader.type = reader.Read16();
	commonHeader.arch = reader.Read16();
	commonHeader.version = reader.Read32();

	// Promote the file class to 64-bit
	// TODO potentially add a setting to allow the user to override header interpretation
	if ((commonHeader.type == ET_EXEC) && (commonHeader.arch == EM_X86_64) && (ident.fileClass == 1))
	{
		ident.fileClass = 2;
		m_logger->LogWarn(
			"Executable file claims to be 32-bit but specifies a 64-bit architecture. It is likely malformed or "
			"malicious. Treating it as 64-bit.");
	}

	// parse Elf64Header
	if (ident.fileClass == 1) // 32-bit ELF
	{
		header.entry = reader.Read32();
		header.programHeaderOffset = reader.Read32();
		header.sectionHeaderOffset = reader.Read32();
		header.flags = reader.Read32();
		header.headerSize = reader.Read16();
		header.programHeaderSize = reader.Read16();
		header.programHeaderCount = reader.Read16();
		header.sectionHeaderSize = reader.Read16();
		header.sectionHeaderCount = reader.Read16();
		header.stringTable = reader.Read16();
	}
	else if (ident.fileClass == 2) // 64-bit ELF
	{
		header.entry = reader.Read64();
		header.programHeaderOffset = reader.Read64();
		header.sectionHeaderOffset = reader.Read64();
		header.flags = reader.Read32();
		header.headerSize = reader.Read16();
		header.programHeaderSize = reader.Read16();
		header.programHeaderCount = reader.Read16();
		header.sectionHeaderSize = reader.Read16();
		header.sectionHeaderCount = reader.Read16();
		header.stringTable = reader.Read16();
	}
	else
	{
		errorMsg = "invalid file class";
		return 0;
	}

	map<string, Ref<Metadata>> metadataMap = {
		{"EI_CLASS",    new Metadata((uint64_t) ident.fileClass)},
		{"EI_DATA",     new Metadata((uint64_t) ident.encoding)},
		{"EI_OSABI",    new Metadata((uint64_t) ident.os)},
		{"e_type",      new Metadata((uint64_t) commonHeader.type)},
		{"e_machine",   new Metadata((uint64_t) commonHeader.arch)},
		{"e_flags",     new Metadata((uint64_t) header.flags)},
	};

	Ref<Metadata> metadata = new Metadata(metadataMap);
	// retrieve architecture
	// FIXME: Architecture registration methods should perhaps be virtual and take the raw data, or some additional opaque information.

	bool checkForARMBE8 = Settings::Instance()->Get<bool>("files.elf.detectARMBE8Binary");
	if (checkForARMBE8)
		endianness = ((commonHeader.arch == EM_ARM) && (header.flags & EF_ARM_BE8)) ? BigEndian : endianness;

	/* for architectures where .e_machine field doesn't disambiguate between 32/64 (like MIPS),
	   form the conventional alternative id, including the .e_ident[EI_CLASS] field */
	uint32_t altArchId = (ident.fileClass << 16) | commonHeader.arch;

	Ref<Platform> recognizedPlatform = g_elfViewType->RecognizePlatform(commonHeader.arch, endianness, data, metadata);

	if (!recognizedPlatform)
	{
		/* second try with the alternative architecture identifier */
		recognizedPlatform = g_elfViewType->RecognizePlatform(altArchId, endianness, data, metadata);
	}

	if (recognizedPlatform)
	{
		if (plat)
			*plat = recognizedPlatform;
		if (arch)
			*arch = recognizedPlatform->GetArchitecture();
	}
	else
	{
		BNEndianness codeEndianness = endianness;
		if (checkForARMBE8 && (commonHeader.arch == EM_ARM) && (header.flags & EF_ARM_BE8))
			codeEndianness = LittleEndian;

		if (arch)
		{
			*arch = g_elfViewType->GetArchitecture(commonHeader.arch, codeEndianness);

			if (!*arch)
			{
				/* second try with the alternative architecture identifier */
				*arch = g_elfViewType->GetArchitecture(altArchId, codeEndianness);
			}
		}
	}

	return reader.GetOffset();
}


Ref<Settings> ElfViewType::GetLoadSettingsForData(BinaryView* data)
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


	return settings;
}


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifdef DEMO_EDITION
	bool ElfPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		InitElfViewType();
		return true;
	}
}
