#include <algorithm>
#include <cstdint>
#include <sstream>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <tuple>
#ifndef _MSC_VER
#include <cxxabi.h>
#endif
#include "machoview.h"
#include "fatmachoview.h"
#include "universalview.h"
#include "lowlevelilinstruction.h"
#include "rapidjsonwrapper.h"

using namespace BinaryNinja;
using namespace std;


static MachoViewType* g_machoViewType = nullptr;

static string CommandToString(uint32_t lcCommand)
{
	switch(lcCommand)
	{
		case LC_REQ_DYLD: return "LC_REQ_DYLD";
		case LC_SEGMENT: return "LC_SEGMENT";
		case LC_SYMTAB: return "LC_SYMTAB";
		case LC_SYMSEG: return "LC_SYMSEG";
		case LC_THREAD: return "LC_THREAD";
		case LC_UNIXTHREAD: return "LC_UNIXTHREAD";
		case LC_LOADFVMLIB: return "LC_LOADFVMLIB";
		case LC_IDFVMLIB: return "LC_IDFVMLIB";
		case LC_IDENT: return "LC_IDENT";
		case LC_FVMFILE: return "LC_FVMFILE";
		case LC_PREPAGE: return "LC_PREPAGE";
		case LC_DYSYMTAB: return "LC_DYSYMTAB";
		case LC_LOAD_DYLIB: return "LC_LOAD_DYLIB";
		case LC_ID_DYLIB: return "LC_ID_DYLIB";
		case LC_LOAD_DYLINKER: return "LC_LOAD_DYLINKER";
		case LC_ID_DYLINKER: return "LC_ID_DYLINKER";
		case LC_PREBOUND_DYLIB: return "LC_PREBOUND_DYLIB";
		case LC_ROUTINES: return "LC_ROUTINES";
		case LC_SUB_FRAMEWORK: return "LC_SUB_FRAMEWORK";
		case LC_SUB_UMBRELLA: return "LC_SUB_UMBRELLA";
		case LC_SUB_CLIENT: return "LC_SUB_CLIENT";
		case LC_SUB_LIBRARY: return "LC_SUB_LIBRARY";
		case LC_TWOLEVEL_HINTS: return "LC_TWOLEVEL_HINTS";
		case LC_PREBIND_CKSUM: return "LC_PREBIND_CKSUM";
		case LC_LOAD_WEAK_DYLIB: return "LC_LOAD_WEAK_DYLIB";
		case LC_SEGMENT_64: return "LC_SEGMENT_64";
		case LC_ROUTINES_64: return "LC_ROUTINES_64";
		case LC_UUID: return "LC_UUID";
		case LC_RPATH: return "LC_RPATH";
		case LC_CODE_SIGNATURE: return "LC_CODE_SIGNATURE";
		case LC_SEGMENT_SPLIT_INFO: return "LC_SEGMENT_SPLIT_INFO";
		case LC_REEXPORT_DYLIB: return "LC_REEXPORT_DYLIB";
		case LC_LAZY_LOAD_DYLIB: return "LC_LAZY_LOAD_DYLIB";
		case LC_ENCRYPTION_INFO: return "LC_ENCRYPTION_INFO";
		case LC_DYLD_INFO: return "LC_DYLD_INFO";
		case LC_DYLD_INFO_ONLY: return "LC_DYLD_INFO_ONLY";
		case LC_LOAD_UPWARD_DYLIB: return "LC_LOAD_UPWARD_DYLIB";
		case LC_VERSION_MIN_MACOSX: return "LC_VERSION_MIN_MACOSX";
		case LC_VERSION_MIN_IPHONEOS: return "LC_VERSION_MIN_IPHONEOS";
		case LC_FUNCTION_STARTS: return "LC_FUNCTION_STARTS";
		case LC_DYLD_ENVIRONMENT: return "LC_DYLD_ENVIRONMENT";
		case LC_MAIN: return "LC_MAIN";
		case LC_DATA_IN_CODE: return "LC_DATA_IN_CODE";
		case LC_SOURCE_VERSION: return "LC_SOURCE_VERSION";
		case LC_DYLIB_CODE_SIGN_DRS: return "LC_DYLIB_CODE_SIGN_DRS";
		case _LC_ENCRYPTION_INFO_64: return "LC_ENCRYPTION_INFO_64";
		case _LC_LINKER_OPTION: return "LC_LINKER_OPTION";
		case _LC_LINKER_OPTIMIZATION_HINT: return "LC_LINKER_OPTIMIZATION_HINT";
		case _LC_VERSION_MIN_TVOS: return "LC_VERSION_MIN_TVOS";
		case LC_VERSION_MIN_WATCHOS: return "LC_VERSION_MIN_WATCHOS";
		case LC_NOTE: return "LC_NOTE";
		case LC_BUILD_VERSION: return "LC_BUILD_VERSION";
		case LC_DYLD_EXPORTS_TRIE: return "LC_DYLD_EXPORTS_TRIE";
		case LC_DYLD_CHAINED_FIXUPS: return "LC_DYLD_CHAINED_FIXUPS";
		default:
		{
			stringstream ss;
			ss << "0x" << std::hex << lcCommand;
			return ss.str();
		}
	}
}


static string BuildPlatformToString(uint32_t platform)
{
	switch (platform)
	{
		case MACHO_PLATFORM_MACOS: return "macos";
		case MACHO_PLATFORM_IOS: return "ios";
		case MACHO_PLATFORM_TVOS: return "tvos";
		case MACHO_PLATFORM_WATCHOS: return "watchos";
		case MACHO_PLATFORM_BRIDGEOS: return "bridgeos";
		default:
		{
			stringstream ss;
			ss << "0x" << std::hex << platform;
			return ss.str();
		}
	}
}


static string BuildToolToString(uint32_t tool)
{
	switch (tool)
	{
		case MACHO_TOOL_CLANG: return "clang";
		case MACHO_TOOL_SWIFT: return "swift";
		case MACHO_TOOL_LD: return "ld";
		default:
		{
			stringstream ss;
			ss << "0x" << std::hex << tool;
			return ss.str();
		}
	}
}


static string BuildToolVersionToString(uint32_t version)
{
	uint32_t major = (version >> 16) & 0xffff;
	uint32_t minor = (version >> 8) & 0xff;
	uint32_t update = version & 0xff;

	stringstream ss;
	ss << major << "." << minor << "." << update;
	return ss.str();
}


void BinaryNinja::InitMachoViewType()
{
	static MachoViewType type;
	BinaryViewType::Register(&type);
	g_machoViewType = &type;
}


static int64_t readSLEB128(DataBuffer& buffer, size_t length, size_t &offset)
{
	uint8_t cur;
	int64_t value = 0;
	size_t shift = 0;
	while (offset < length)
	{
		cur = buffer[offset++];
		value |= (cur & 0x7f) << shift;
		shift += 7;
		if ((cur & 0x80) == 0)
			break;
	}
	value = (value << (64 - shift)) >> (64 - shift);
	return value;
}


static uint64_t readLEB128(DataBuffer& p, size_t end, size_t &offset)
{
	uint64_t result = 0;
	int bit = 0;
	do {
		if (offset >= end)
			return -1;

		uint64_t slice = p[offset] & 0x7f;

		if (bit > 63)
			return -1;
		else {
			result |= (slice << bit);
			bit += 7;
		}
	} while (p[offset++] & 0x80);
	return result;
}


uint64_t readValidULEB128(DataBuffer& buffer, size_t& cursor)
{
	uint64_t value = readLEB128(buffer, buffer.GetLength(), cursor);
	if ((int64_t)value == -1)
		throw ReadException();
	return value;
}


MachoView::MachoView(const string& typeName, BinaryView* data, bool parseOnly): BinaryView(typeName, data->GetFile(), data),
	m_universalImageOffset(0), m_parseOnly(parseOnly)
{
	CreateLogger("BinaryView");
	m_logger = CreateLogger("BinaryView.MachoView");

	m_backedByDatabase = data->GetFile()->IsBackedByDatabase(typeName);

	Ref<BinaryViewType> universalViewType = BinaryViewType::GetByName("Universal");
	bool isUniversal = (universalViewType && universalViewType->IsTypeValidForData(data));

	Ref<Settings> viewSettings = Settings::Instance();
	m_extractMangledTypes = viewSettings->Get<bool>("analysis.extractTypesFromMangledNames", data);
	m_simplifyTemplates = viewSettings->Get<bool>("analysis.types.templateSimplifier", data);

	Ref<Settings> settings = data->GetLoadSettings(typeName);
	if (settings && settings->Contains("loader.macho.universalImageOffset"))
	{
		settings->SetResourceId(typeName);
		m_universalImageOffset = settings->Get<uint64_t>("loader.macho.universalImageOffset", data);
	}
	else if (isUniversal)
	{
		Ref<Settings> loadSettings = universalViewType->GetLoadSettingsForData(data);
		if (loadSettings && loadSettings->Contains("loader.universal.architectures"))
		{
			string json = loadSettings->Get<string>("loader.universal.architectures");
			rapidjson::Document jsonArchitectures;
			jsonArchitectures.Parse(json.data(), json.size());
			if (!json.size() || jsonArchitectures.HasParseError())
				throw MachoFormatException("Mach-O view could not be created! Json parse error.");
			if (!jsonArchitectures.IsArray() || jsonArchitectures.Empty())
				throw MachoFormatException("Mach-O view could not be created! Json data error.");

			// Select the object file based on architecture preference.
			// Note: This code is duplicated in options.cpp
			vector<string> architectures;
			for (const auto& entry : jsonArchitectures.GetArray())
				architectures.push_back(entry["architecture"].GetString());
			auto archPref = Settings::Instance()->Get<vector<string>>("files.universal.architecturePreference");
			int archIndex = 0;
			if (auto result = find_first_of(archPref.begin(), archPref.end(), architectures.begin(), architectures.end()); result != archPref.end())
				archIndex = std::find(architectures.begin(), architectures.end(), *result) - architectures.begin();

			const auto& archEntry = jsonArchitectures[archIndex];
			loadSettings = Settings::Instance(GetUniqueIdentifierString());
			loadSettings->SetResourceId(typeName);
			loadSettings->DeserializeSchema(archEntry["loadSchema"].GetString());
			data->SetLoadSettings(typeName, loadSettings);
			if (!m_file->IsBackedByDatabase(typeName))
			{
				auto defaultSettings = loadSettings->SerializeSettings(Ref<BinaryView>(), SettingsDefaultScope);
				loadSettings->DeserializeSettings(defaultSettings, data, SettingsResourceScope);
			}

			m_universalImageOffset = loadSettings->Get<uint64_t>("loader.macho.universalImageOffset", data);

			// NOTE: this silences the 'Updated load schema detected' warning. There is some chicken/egg stuff here.
			loadSettings->UpdateProperty("loader.macho.universalImageOffset", "default", m_universalImageOffset);
		}
	}

	m_header = HeaderForAddress(data, 0, true);
}


MachOHeader MachoView::HeaderForAddress(BinaryView* data, uint64_t address, bool isMainHeader, std::string identifierPrefix)
{
	MachOHeader header{};
	header.isMainHeader = isMainHeader;

	header.identifierPrefix = identifierPrefix;
	header.stringList = new DataBuffer();

	std::string errorMsg;
	if (isMainHeader) {
		header.loadCommandOffset = g_machoViewType->ParseHeaders(data, m_universalImageOffset + address, header.ident, &m_arch, &m_plat, errorMsg);
		if (!header.loadCommandOffset)
			throw MachoFormatException(errorMsg);
	}
	else
	{
		// address is a Raw file offset
		BinaryReader subReader(data);
		subReader.Seek(address);

		header.ident.magic = subReader.Read32();

		BNEndianness endianness;
		if (header.ident.magic == MH_MAGIC || header.ident.magic == MH_MAGIC_64)
			endianness = LittleEndian;
		else if (header.ident.magic == MH_CIGAM || header.ident.magic == MH_CIGAM_64)
			endianness = BigEndian;
		else
		{
			throw ReadException();
		}

		subReader.SetEndianness(endianness);
		header.ident.cputype    = subReader.Read32();
		header.ident.cpusubtype = subReader.Read32();
		header.ident.filetype   = subReader.Read32();
		header.ident.ncmds      = subReader.Read32();
		header.ident.sizeofcmds = subReader.Read32();
		header.ident.flags      = subReader.Read32();
		if ((header.ident.cputype & MachOABIMask) == MachOABI64) // address size == 8
		{
			header.ident.reserved = subReader.Read32();
		}
		header.loadCommandOffset = subReader.GetOffset();
	}


	if (isMainHeader)
	{
		if (header.ident.magic == MH_MAGIC || header.ident.magic == MH_MAGIC_64)
		{
			m_endian = LittleEndian;
			m_logger->LogDebug("Recognized Little Endian Mach-O");
		}
		else // (header.ident.magic == MH_CIGAM || header.ident.magic == MH_CIGAM_64)
		{
			m_endian = BigEndian;
			m_logger->LogDebug("Recognized Big Endian Mach-O");
		}
	}

	BinaryReader reader(data);
	reader.SetEndianness(m_endian);
	reader.SetVirtualBase(m_universalImageOffset);
	reader.Seek(header.loadCommandOffset);

	if (isMainHeader)
	{
		m_objectFile = header.ident.filetype == MH_OBJECT;
		m_dylibFile = header.ident.filetype == MH_DYLIB;
		m_relocatable = ((header.ident.flags & MH_PIE) > 0) || m_objectFile || m_dylibFile;
		m_archId = header.ident.cputype;
		m_addressSize = (header.ident.cputype & MachOABIMask) == MachOABI64 ? 8 : 4;
	}

	bool first = true;
	// Parse segment commands
	try
	{
		m_logger->LogDebug("ident.ncmds: %d\n", header.ident.ncmds);
		for (size_t i = 0; i < header.ident.ncmds; i++)
		{
			load_command load;
			segment_command_64 segment64;
			section_64 sect;
			memset(&sect, 0, sizeof(sect));
			size_t curOffset = reader.GetOffset();
			load.cmd = reader.Read32();
			load.cmdsize = reader.Read32();
			size_t nextOffset = curOffset + load.cmdsize;
			m_logger->LogDebug("Segment cmd: %08x - cmdsize: %08x - ", load.cmd, load.cmdsize);
			if (load.cmdsize < sizeof(load_command))
				throw MachoFormatException("unable to read header");

			switch (load.cmd)
			{
			case LC_MAIN:
			{
				uint64_t entryPoint = reader.Read64();
				m_logger->LogDebug("LC_MAIN entryPoint: %#016" PRIx64, entryPoint);
				header.entryPoints.push_back({entryPoint, true});
				(void)reader.Read64(); // Stack start
				break;
			}
			case LC_SEGMENT: //map the 32bit version to 64 bits
				m_logger->LogDebug("LC_SEGMENT\n");
				segment64.cmd = LC_SEGMENT_64;
				reader.Read(&segment64.segname, 16);
				segment64.vmaddr = reader.Read32();
				segment64.vmsize = reader.Read32();
				segment64.fileoff = reader.Read32() + m_universalImageOffset;
				segment64.filesize = reader.Read32();
				segment64.maxprot = reader.Read32();
				segment64.initprot = reader.Read32();
				segment64.nsects = reader.Read32();
				segment64.flags = reader.Read32();
				if (first)
				{
						if (!((header.ident.flags & MH_SPLIT_SEGS) || header.ident.cputype == MACHO_CPU_TYPE_X86_64)
							|| (segment64.flags & MACHO_VM_PROT_WRITE))
						{
							header.relocationBase = segment64.vmaddr;
							first = false;
						}
				}
				m_logger->LogDebug("\tName:     %s\n" \
					"\tCmd:      %#08"  PRIx32 "\n" \
					"\tvmaddr:   %#016" PRIx64 "\n" \
					"\tvmsize:   %#016" PRIx64 "\n" \
					"\tfileoff:  %#016" PRIx64 "\n" \
					"\tfilesize: %#016" PRIx64 "\n" \
					"\tmaxprot:  %#08"  PRIx32 "\n" \
					"\tinitprot: %#08"  PRIx32 "\n" \
					"\tnsects:   %#08"  PRIx32 "\n" \
					"\tflags:    %#08"  PRIx32 "\n",
					(char*)&segment64.segname,
					segment64.cmd,
					segment64.vmaddr,
					segment64.vmsize,
					segment64.fileoff,
					segment64.filesize,
					segment64.maxprot,
					segment64.initprot,
					segment64.nsects,
					segment64.flags);
				for (size_t j = 0; j < segment64.nsects; j++)
				{
						reader.Read(&sect.sectname, 16);
						reader.Read(&sect.segname, 16);
						sect.addr = reader.Read32();
						sect.size = reader.Read32();
						sect.offset = reader.Read32();
						sect.align = reader.Read32();
						sect.reloff = reader.Read32();
						sect.nreloc = reader.Read32();
						sect.flags = reader.Read32();
						sect.reserved1 = reader.Read32();
						sect.reserved2 = reader.Read32();
						// if the segment isn't mapped into virtual memory don't add the corresponding sections.
						if (segment64.vmsize > 0)
						{
							header.sections.push_back(sect);
							m_allSections.push_back(sect);
						}
						else
							m_logger->LogInfo("Omitting section %16s at %#" PRIx64 " corresponding to segment %16s which is not mapped into memory", (char*)&sect.sectname, sect.addr, (char*)&sect.segname);

						m_logger->LogDebug("\t\tSegName:  %16s\n" \
							"\t\tSectName: %16s\n" \
							"\t\tAddr:     %#" PRIx64 "\n" \
							"\t\tSize:     %#" PRIx64 "\n" \
							"\t\tOffset:   %#" PRIx32 "\n" \
							"\t\tAlign:    %#" PRIx32 "\n" \
							"\t\tReloff:   %#" PRIx32 "\n" \
							"\t\tNReloc:   %#" PRIx32 "\n" \
							"\t\tFlags:    %#" PRIx32 "\n" \
							"\t\tReserved1:%#" PRIx32 "\n" \
							"\t\tReserved2:%#" PRIx32 "\n" \
							"\t\t------------------------\n",
							(char*)&sect.segname,
							(char*)&sect.sectname,
							sect.addr,
							sect.size,
							sect.offset,
							sect.align,
							sect.reloff,
							sect.nreloc,
							sect.flags,
							sect.reserved1,
							sect.reserved2);
						if (!strncmp(sect.sectname, "__mod_init_func", 15))
							header.moduleInitSections.push_back(sect);
						if ((sect.flags & (S_ATTR_SELF_MODIFYING_CODE | S_SYMBOL_STUBS)) == (S_ATTR_SELF_MODIFYING_CODE | S_SYMBOL_STUBS))
							header.symbolStubSections.push_back(sect);
						if ((sect.flags & S_NON_LAZY_SYMBOL_POINTERS) == S_NON_LAZY_SYMBOL_POINTERS)
							header.symbolPointerSections.push_back(sect);
						if ((sect.flags & S_LAZY_SYMBOL_POINTERS) == S_LAZY_SYMBOL_POINTERS)
							header.symbolPointerSections.push_back(sect);
				}
				header.segments.push_back(segment64);
				m_allSegments.push_back(segment64);
				break;
			case LC_SEGMENT_64:
				m_logger->LogDebug("LC_SEGMENT_64\n");
				segment64.cmd = LC_SEGMENT_64;
				reader.Read(&segment64.segname, 16);
				segment64.vmaddr = reader.Read64();
				segment64.vmsize = reader.Read64();
				segment64.fileoff = reader.Read64() + m_universalImageOffset;
				segment64.filesize = reader.Read64();
				segment64.maxprot = reader.Read32();
				segment64.initprot = reader.Read32();
				segment64.nsects = reader.Read32();
				segment64.flags = reader.Read32();
				if (first)
				{
						if (!((header.ident.flags & MH_SPLIT_SEGS) || header.ident.cputype == MACHO_CPU_TYPE_X86_64)
							|| (segment64.flags & MACHO_VM_PROT_WRITE))
						{
							header.relocationBase = segment64.vmaddr;
							first = false;
						}
				}
				m_logger->LogDebug(
					"\tName:     %s\n" \
					"\tCmd:      %#08"  PRIx32 "\n" \
					"\tvmaddr:   %#016" PRIx64 "\n" \
					"\tvmsize:   %#016" PRIx64 "\n" \
					"\tfileoff:  %#016" PRIx64 "\n" \
					"\tfilesize: %#016" PRIx64 "\n" \
					"\tmaxprot:  %#08"  PRIx32 "\n" \
					"\tinitprot: %#08"  PRIx32 "\n" \
					"\tnsects:   %#08"  PRIx32 "\n" \
					"\tflags:    %#08"  PRIx32 "\n",
					(char*)&segment64.segname,
					segment64.cmd,
					segment64.vmaddr,
					segment64.vmsize,
					segment64.fileoff,
					segment64.filesize,
					segment64.maxprot,
					segment64.initprot,
					segment64.nsects,
					segment64.flags);
				m_logger->LogDebug("\t\t------------------------\n");
				for (size_t j = 0; j < segment64.nsects; j++)
				{
						reader.Read(&sect.sectname, 16);
						reader.Read(&sect.segname, 16);
						sect.addr = reader.Read64();
						sect.size = reader.Read64();
						sect.offset = reader.Read32();
						sect.align = reader.Read32();
						sect.reloff = reader.Read32();
						sect.nreloc = reader.Read32();
						sect.flags = reader.Read32();
						sect.reserved1 = reader.Read32();
						sect.reserved2 = reader.Read32();
						sect.reserved3 = reader.Read32();
						// if the segment isn't mapped into virtual memory don't add the corresponding sections.
						if (segment64.vmsize > 0)
						{
							header.sections.push_back(sect);
							m_allSections.push_back(sect);
						}
						else
							m_logger->LogInfo("Omitting section %16s at %#" PRIx64 " corresponding to segment %16s which is not mapped into memory", (char*)&sect.sectname, sect.addr, (char*)&sect.segname);
						m_logger->LogDebug(
							"\t\tSegName:  %16s\n" \
							"\t\tSectName: %16s\n" \
							"\t\tAddr:     %#" PRIx64 "\n" \
							"\t\tSize:     %#" PRIx64 "\n" \
							"\t\tOffset:   %#" PRIx32 "\n" \
							"\t\tAlign:    %#" PRIx32 "\n" \
							"\t\tReloff:   %#" PRIx32 "\n" \
							"\t\tNReloc:   %#" PRIx32 "\n" \
							"\t\tFlags:    %#" PRIx32 "\n" \
							"\t\tReserved1:%#" PRIx32 "\n" \
							"\t\tReserved2:%#" PRIx32 "\n" \
							"\t\tReserved3:%#" PRIx32 "\n" \
							"\t\t------------------------\n",
							(char*)&sect.segname,
							(char*)&sect.sectname,
							sect.addr,
							sect.size,
							sect.offset,
							sect.align,
							sect.reloff,
							sect.nreloc,
							sect.flags,
							sect.reserved1,
							sect.reserved2,
							sect.reserved3);
						if (!strncmp(sect.sectname, "__mod_init_func", 15))
							header.moduleInitSections.push_back(sect);
						if ((sect.flags & (S_ATTR_SELF_MODIFYING_CODE | S_SYMBOL_STUBS)) == (S_ATTR_SELF_MODIFYING_CODE | S_SYMBOL_STUBS))
							header.symbolStubSections.push_back(sect);
						if ((sect.flags & S_NON_LAZY_SYMBOL_POINTERS) == S_NON_LAZY_SYMBOL_POINTERS)
							header.symbolPointerSections.push_back(sect);
						if ((sect.flags & S_LAZY_SYMBOL_POINTERS) == S_LAZY_SYMBOL_POINTERS)
							header.symbolPointerSections.push_back(sect);
				}
				header.segments.push_back(segment64);
				m_allSegments.push_back(segment64);
				break;
			case LC_ROUTINES: //map the 32bit version to 64bits
				m_logger->LogDebug("LC_REOUTINES\n");
				header.routines64.cmd = LC_ROUTINES_64;
				header.routines64.init_address = reader.Read32();
				header.routines64.init_module = reader.Read32();
				header.routines64.reserved1 = reader.Read32();
				header.routines64.reserved2 = reader.Read32();
				header.routines64.reserved3 = reader.Read32();
				header.routines64.reserved4 = reader.Read32();
				header.routines64.reserved5 = reader.Read32();
				header.routines64.reserved6 = reader.Read32();
				header.routinesPresent = true;
				m_logger->LogDebug("\tinit_address: %016" PRIx64 "\n\tinit_module: %08" PRIx64 "\n",
					header.routines64.init_address, header.routines64.init_module);
				break;
			case LC_ROUTINES_64:
				m_logger->LogDebug("LC_REOUTINES_64\n");
				header.routines64.cmd = LC_ROUTINES_64;
				header.routines64.init_address = reader.Read64();
				header.routines64.init_module = reader.Read64();
				header.routines64.reserved1 = reader.Read64();
				header.routines64.reserved2 = reader.Read64();
				header.routines64.reserved3 = reader.Read64();
				header.routines64.reserved4 = reader.Read64();
				header.routines64.reserved5 = reader.Read64();
				header.routines64.reserved6 = reader.Read64();
				header.routinesPresent = true;
				m_logger->LogDebug("\tinit_address: %016" PRIx64 "\n\tinit_module: %08" PRIx64 "\n",
					header.routines64.init_address, header.routines64.init_module);
				break;
			case LC_FUNCTION_STARTS:
				m_logger->LogDebug("LC_FUNCTION_STARTS\n");
				header.functionStarts.funcoff = reader.Read32();
				header.functionStarts.funcsize = reader.Read32();
				header.functionStartsPresent = true;
				m_logger->LogDebug("\tFunction Starts:\n\toffset: %#08" PRIx32 "\n\tsize: %#08" PRIx32 "\n",
					header.functionStarts.funcoff, header.functionStarts.funcsize);
				break;
			case LC_SYMTAB:
				m_logger->LogDebug("LC_SYMTAB\n");
				header.symtab.symoff  = reader.Read32();
				header.symtab.nsyms   = reader.Read32();
				header.symtab.stroff  = reader.Read32();
				header.symtab.strsize = reader.Read32();
				reader.Seek(header.symtab.stroff);
				header.stringList->Append(reader.Read(header.symtab.strsize));
				header.stringListSize = header.symtab.strsize;
				m_logger->LogDebug("\tstrsize: %08x\n" \
					"\tstroff: %08x\n" \
					"\tnsyms: %08x\n",
					header.symtab.strsize,
					header.symtab.stroff,
					header.symtab.nsyms);
				break;
			case LC_DYSYMTAB:
				m_logger->LogDebug("LC_DYSYMTAB\n");
				header.dysymtab.ilocalsym = reader.Read32();
				header.dysymtab.nlocalsym = reader.Read32();
				header.dysymtab.iextdefsym = reader.Read32();
				header.dysymtab.nextdefsym = reader.Read32();
				header.dysymtab.iundefsym = reader.Read32();
				header.dysymtab.nundefsym = reader.Read32();
				header.dysymtab.tocoff = reader.Read32();
				header.dysymtab.ntoc = reader.Read32();
				header.dysymtab.modtaboff = reader.Read32();
				header.dysymtab.nmodtab = reader.Read32();
				header.dysymtab.extrefsymoff = reader.Read32();
				header.dysymtab.nextrefsyms = reader.Read32();
				header.dysymtab.indirectsymoff = reader.Read32();
				header.dysymtab.nindirectsyms = reader.Read32();
				header.dysymtab.extreloff = reader.Read32();
				header.dysymtab.nextrel = reader.Read32();
				header.dysymtab.locreloff = reader.Read32();
				header.dysymtab.nlocrel = reader.Read32();
				m_logger->LogDebug("\theader.dysymtab.ilocalsym      0x%08x\n"\
					"\theader.dysymtab.nlocalsym      0x%08x\n"\
					"\theader.dysymtab.iextdefsym     0x%08x\n"\
					"\theader.dysymtab.nextdefsym     0x%08x\n"\
					"\theader.dysymtab.iundefsym      0x%08x\n"\
					"\theader.dysymtab.nundefsym      0x%08x\n"\
					"\theader.dysymtab.tocoff         0x%08x\n"\
					"\theader.dysymtab.ntoc           0x%08x\n"\
					"\theader.dysymtab.modtaboff      0x%08x\n"\
					"\theader.dysymtab.nmodtab        0x%08x\n"\
					"\theader.dysymtab.extrefsymoff   0x%08x\n"\
					"\theader.dysymtab.nextrefsyms    0x%08x\n"\
					"\theader.dysymtab.indirectsymoff 0x%08x\n"\
					"\theader.dysymtab.nindirectsyms  0x%08x\n"\
					"\theader.dysymtab.extreloff      0x%08x\n"\
					"\theader.dysymtab.nextrel        0x%08x\n"\
					"\theader.dysymtab.locreloff      0x%08x\n"\
					"\theader.dysymtab.nlocrel        0x%08x\n",
					header.dysymtab.ilocalsym,
					header.dysymtab.nlocalsym,
					header.dysymtab.iextdefsym,
					header.dysymtab.nextdefsym,
					header.dysymtab.iundefsym,
					header.dysymtab.nundefsym,
					header.dysymtab.tocoff,
					header.dysymtab.ntoc,
					header.dysymtab.modtaboff,
					header.dysymtab.nmodtab,
					header.dysymtab.extrefsymoff,
					header.dysymtab.nextrefsyms,
					header.dysymtab.indirectsymoff,
					header.dysymtab.nindirectsyms,
					header.dysymtab.extreloff,
					header.dysymtab.nextrel,
					header.dysymtab.locreloff,
					header.dysymtab.nlocrel);
				header.dysymPresent = true;
				break;
			case LC_DYLD_CHAINED_FIXUPS:
				m_logger->LogDebug("LC_DYLD_CHAINED_FIXUPS\n");
				header.chainedFixups.dataoff = reader.Read32();
				header.chainedFixups.datasize = reader.Read32();
				header.chainedFixupsPresent = true;
				break;
			case LC_DYLD_INFO:
			case LC_DYLD_INFO_ONLY:
				m_logger->LogDebug("LC_DYLD_INFO\n");
				header.dyldInfo.rebase_off = reader.Read32();
				header.dyldInfo.rebase_size = reader.Read32();
				header.dyldInfo.bind_off = reader.Read32();
				header.dyldInfo.bind_size = reader.Read32();
				header.dyldInfo.weak_bind_off = reader.Read32();
				header.dyldInfo.weak_bind_size = reader.Read32();
				header.dyldInfo.lazy_bind_off = reader.Read32();
				header.dyldInfo.lazy_bind_size = reader.Read32();
				header.dyldInfo.export_off = reader.Read32();
				header.dyldInfo.export_size = reader.Read32();
				header.exportTrie.dataoff = header.dyldInfo.export_off;
				header.exportTrie.datasize = header.dyldInfo.export_size;
				header.exportTriePresent = true;
				header.dyldInfoPresent = true;
				break;
			case LC_DYLD_EXPORTS_TRIE:
				m_logger->LogDebug("LC_DYLD_EXPORTS_TRIE\n");
				header.exportTrie.dataoff = reader.Read32();
				header.exportTrie.datasize = reader.Read32();
				header.exportTriePresent = true;
				break;
			case LC_THREAD:
			case LC_UNIXTHREAD:
				while (reader.GetOffset() < nextOffset)
				{
						thread_command thread;
						thread.flavor = reader.Read32();
						thread.count = reader.Read32();
						m_logger->LogDebug("LC_THREAD\\LC_UNIXTHREAD\n");
						switch (m_archId)
						{
						case MachOx64:
							m_logger->LogDebug("x86_64 Thread state\n");
							if (thread.flavor != X86_THREAD_STATE64)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							//This wont be big endian so we can just read the whole thing
							reader.Read(&thread.statex64, sizeof(thread.statex64));
							header.entryPoints.push_back({thread.statex64.rip, false});
							break;
						case MachOx86:
							m_logger->LogDebug("x86 Thread state\n");
							if (thread.flavor != X86_THREAD_STATE32)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							//This wont be big endian so we can just read the whole thing
							reader.Read(&thread.statex86, sizeof(thread.statex86));
							header.entryPoints.push_back({thread.statex86.eip, false});
							break;
						case MachOArm:
							m_logger->LogDebug("Arm Thread state\n");
							if (thread.flavor != _ARM_THREAD_STATE)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							//This wont be big endian so we can just read the whole thing
							reader.Read(&thread.statearmv7, sizeof(thread.statearmv7));
							header.entryPoints.push_back({thread.statearmv7.r15, false});
							break;
						case MachOAarch64:
						case MachOAarch6432:
							m_logger->LogDebug("Aarch64 Thread state\n");
							if (thread.flavor != _ARM_THREAD_STATE64)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							reader.Read(&thread.stateaarch64, sizeof(thread.stateaarch64));
							header.entryPoints.push_back({thread.stateaarch64.pc, false});
							break;
						case MachOPPC:
							m_logger->LogDebug("PPC Thread state\n");
							if (thread.flavor != PPC_THREAD_STATE)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							//Read individual entries for endian reasons
							header.entryPoints.push_back({reader.Read32(), false});
							(void)reader.Read32();
							(void)reader.Read32();
							//Read the rest of the structure
							(void)reader.Read(&thread.stateppc.r1, sizeof(thread.stateppc) - (3 * 4));
							break;
						case MachOPPC64:
							m_logger->LogDebug("PPC64 Thread state\n");
							if (thread.flavor != PPC_THREAD_STATE64)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							header.entryPoints.push_back({reader.Read64(), false});
							(void)reader.Read64();
							(void)reader.Read64(); // Stack start
							(void)reader.Read(&thread.stateppc64.r1, sizeof(thread.stateppc64) - (3 * 8));
							break;
						default:
							m_logger->LogError("Unknown archid: %x", m_archId);
						}
				}
				break;
			case LC_LOAD_DYLIB:
			{
				uint32_t offset = reader.Read32();
				reader.Read32(); // timestamp
				uint32_t currentVersion = reader.Read32();
				if (offset < nextOffset)
				{
						reader.Seek(curOffset + offset);
						string libname = reader.ReadCString();
						auto version = BuildToolVersionToString(currentVersion);
						header.dylibs.push_back({libname, version});
				}
			}
			break;
			case LC_BUILD_VERSION:
			{
				m_logger->LogDebug("LC_BUILD_VERSION:");
				header.buildVersion.platform = reader.Read32();
				header.buildVersion.minos = reader.Read32();
				header.buildVersion.sdk = reader.Read32();
				header.buildVersion.ntools = reader.Read32();
				m_logger->LogDebug("Platform: %s", BuildPlatformToString(header.buildVersion.platform).c_str());
				m_logger->LogDebug("MinOS: %s", BuildToolVersionToString(header.buildVersion.minos).c_str());
				m_logger->LogDebug("SDK: %s", BuildToolVersionToString(header.buildVersion.sdk).c_str());
				for (uint32_t i = 0; (i < header.buildVersion.ntools) && (i < 10); i++)
				{
						uint32_t tool = reader.Read32();
						uint32_t version = reader.Read32();
						header.buildToolVersions.push_back({tool, version});
						m_logger->LogDebug("Build Tool: %s: %s", BuildToolToString(tool).c_str(), BuildToolVersionToString(version).c_str());
				}
				break;
			}
			case LC_FILESET_ENTRY:
			{
				if (isMainHeader)
				{
					uint64_t vmAddr = reader.Read64();
					uint64_t fAddr = reader.Read64();
					uint64_t strOff = reader.Read32() + curOffset;
					reader.Seek(strOff);
					auto identPrefix = reader.ReadCString(load.cmdsize - strOff);
					MachOHeader subHeader = HeaderForAddress(data, fAddr, false, identPrefix);
					subHeader.textBase = vmAddr;
					m_subHeaders[vmAddr] = subHeader;
				}
				else {
					throw ReadException();
				}
				break;
			}
			default:
				m_logger->LogDebug("Unhandled command: %s : %" PRIu32 "\n", CommandToString(load.cmd).c_str(), load.cmdsize);
				break;
			}
			if (reader.GetOffset() != nextOffset)
			{
				m_logger->LogDebug("Didn't parse load command: %s fully %" PRIx64 ":%" PRIxPTR, CommandToString(load.cmd).c_str(), reader.GetOffset(), nextOffset);
			}
			reader.Seek(nextOffset);
		}
	}
	catch (ReadException&)
	{
		throw MachoFormatException("Mach-O section headers invalid");
	}

	return header;
}


void MachoView::RebaseThreadStarts(BinaryReader& virtualReader, vector<uint32_t>& threadStarts, uint64_t stepMultiplier)
{
	std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();

	// create a dummy relocation to handle tagged pointers
	BNRelocationInfo reloc;
	memset(&reloc, 0, sizeof(BNRelocationInfo));
	reloc.type = StandardRelocationType;
	reloc.size = 8;
	reloc.nativeType = BINARYNINJA_MANUAL_RELOCATION;

	size_t numReg = 0;
	size_t numAuth = 0;
	uint64_t imageBase = GetStart();
	for (auto threadStart : threadStarts)
	{
		if (threadStart == 0xffffffff)
			break;

		m_logger->LogDebug("Rebasing thread chain start: 0x%x", threadStart);
		try
		{
			uint64_t curAddr = imageBase + threadStart;
			virtualReader.Seek(curAddr);
			while (true)
			{
				if (!IsOffsetBackedByFile(virtualReader.GetOffset()))
				{
					m_logger->LogError("Chained address: 0x%" PRIx64 " in thread start: 0x%x not backed by file!", virtualReader.GetOffset(), threadStart);
					break;
				}

				// read tagged pointer
				uint64_t val = virtualReader.Read64();
				bool isAuthenticated = (val & (1ULL << 63)) != 0;
				bool isRebase = (val & (1ULL << 62)) == 0;
				if (isRebase)
				{
					// calculate new target value
					uint64_t tgtVal;
					if (isAuthenticated)
					{
						numAuth++;
						tgtVal = (val & 0xFFFFFFFF) + imageBase;
					}
					else
					{
						numReg++;
						uint64_t top8Bits = val & 0x0007F80000000000ULL;
						uint64_t bottom43Bits = val & 0x000007FFFFFFFFFFULL;
						tgtVal = (top8Bits << 13) | (((int64_t)(bottom43Bits << 21) >> 21) & 0x00FFFFFFFFFFFFFF);
						tgtVal += m_imageBaseAdjustment;
					}

					reloc.address = curAddr;
					DefineRelocation(m_arch, reloc, tgtVal, reloc.address);
				}

				// seek to next tagged pointer
				val &= ~(1ULL << 62); // handle bind bit
				uint64_t delta = (val & 0x3FF8000000000000) >> 51;
				delta *= stepMultiplier;
				if (!delta)
					break;

				curAddr += delta;
				virtualReader.Seek(curAddr);
			}
		}
		catch (ReadException&)
		{
			m_logger->LogError("Failed rebasing thread start at: 0x%x", threadStart);
		}
	}

	std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
	double t = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() / 1000.0;
	m_logger->LogInfo("Rebasing thread starts took %.3f seconds. Updated %" PRIuPTR " pointers (authenticated: %" PRIuPTR ", regular: %" PRIuPTR ").", t, numAuth + numReg, numAuth, numReg);
}


bool MachoView::IsValidFunctionStart(uint64_t addr)
{
	uint8_t opcode[BN_MAX_INSTRUCTION_LENGTH];
	size_t opLen = Read(opcode, addr, m_arch->GetMaxInstructionLength());
	if (!opLen)
		return false;

	Ref<LowLevelILFunction> ilFunc = new LowLevelILFunction(m_arch, nullptr);
	ilFunc->SetCurrentAddress(m_arch, addr);
	m_arch->GetInstructionLowLevelIL(opcode, addr, opLen, *ilFunc);
	for (size_t i = 0; i < ilFunc->GetInstructionCount(); i++)
	{
		const auto& instr = ilFunc->GetInstruction(i);
		if (instr.operation == LLIL_UNDEF)
			return false;
	}

	return true;
}


void MachoView::ParseFunctionStarts(Platform* platform, uint64_t textBase, function_starts_command functionStarts)
{
	BinaryReader reader(GetParentView());
	reader.SetEndianness(m_endian);
	reader.SetVirtualBase(m_universalImageOffset);
	try
	{
		if (m_header.ident.filetype == MH_DSYM)
		{
			m_logger->LogDebug("Skipping LC_FUNCTION_STARTS parsing");
			return;
		}

		reader.Seek(functionStarts.funcoff);
		DataBuffer buffer = reader.Read(functionStarts.funcsize);
		size_t i = 0;
		uint64_t curfunc = textBase;
		uint64_t curOffset = 0;

		while (i < functionStarts.funcsize)
		{
			curOffset = readLEB128(buffer, functionStarts.funcsize, i);
			if (curOffset == 0)
				continue;
			curfunc += curOffset;
			uint64_t target = curfunc;
			if (!IsValidFunctionStart(target))
			{
				m_logger->LogWarn("Possible error processing LC_FUNCTION_STARTS! Not adding function at: 0x%" PRIx64 "\n", target);
				continue;
			}
			Ref<Platform> targetPlatform = platform->GetAssociatedPlatformByAddress(target);
			AddFunctionForAnalysis(targetPlatform, target);
			m_logger->LogDebug("Adding function start: %#" PRIx64 "\n", curfunc);
		}
	}
	catch (ReadException&)
	{
		m_logger->LogDebug("LC_FUNCTION_STARTS command invalid");
	}
}


bool MachoView::ParseRelocationEntry(const relocation_info& info, uint64_t start, BNRelocationInfo& result)
{
	// struct BNRelocationInfo
	// {
	// 	BNRelocationType type; // BinaryNinja Relocation Type
	// 	bool pcRelative;       // PC Relative or Absolute (subtract address from relocation)
	// 	bool baseRelative;   // Relative to start of module (Add module base to relocation)
	// 	size_t size;         // Size of the data to be written
	// 	size_t truncateSize; // After addition/subtraction truncate to
	// 	uint64_t nativeType; // Base type from relocation entry
	// 	size_t addend;       // Addend value from relocation entry
	// 	bool hasSign;        // Addend should be subtracted
	// 	bool implicitAddend; // Addend should be read from the BinaryView
	// 	bool external;       // Relocation entry points to external symbol
	// 	size_t symbolIndex;  // Index into symbol table
	// 	size_t sectionIndex; // Index into the section table
	// 	uint64_t address;    // Absolute address or segment offset
	// };
	m_logger->LogDebug("\tr_address:   %" PRIx32 " + %" PRIx64 " = %" PRIx64, info.r_address, start, info.r_address + start);
	m_logger->LogDebug("\tr_symbolnum: %" PRIx32, info.r_symbolnum);
	m_logger->LogDebug("\tr_pcrel:     %" PRIx32, info.r_pcrel);
	m_logger->LogDebug("\tr_length:    %" PRIx32, info.r_length);
	m_logger->LogDebug("\tr_extern:    %" PRIx32, info.r_extern);
	m_logger->LogDebug("\tr_type:      %" PRIx32, info.r_type);
	if (m_objectFile && (info.r_address & R_SCATTERED))
	{
		m_logger->LogError("Scattered Relocations not currently supported");
		return false;
	}

	switch (info.r_length)
	{
	case 0: result.size = 1; break;
	case 1: result.size = 2; break;
	case 2: result.size = 4; break;
	case 3: result.size = 8; break;
	}
	result.address = start + info.r_address;
	result.truncateSize = result.size;
	result.pcRelative = info.r_pcrel;
	result.baseRelative = start == GetStart();
	result.nativeType = info.r_type;
	result.addend = 0;
	result.hasSign = false;
	result.implicitAddend = false;
	result.external = info.r_extern;
	if (result.external)
		result.symbolIndex = info.r_symbolnum;
	else
		result.sectionIndex = info.r_symbolnum;
	return true;
}


bool MachoView::Init()
{
	Ref<Settings> settings = GetLoadSettings(GetTypeName());
	std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();
	BinaryReader reader(GetParentView());
	reader.SetEndianness(m_endian);
	reader.SetVirtualBase(m_universalImageOffset);
	BinaryReader virtualReader(this);
	virtualReader.SetEndianness(m_endian);

	uint64_t initialImageBase = 0;
	bool initialImageBaseSet = false;
	string preferredImageBaseDesc;
	for (const auto& i : m_header.segments)
	{
		if ((i.initprot == MACHO_VM_PROT_NONE) || (!i.vmsize))
			continue;

		if (!initialImageBaseSet)
		{
			initialImageBase = i.vmaddr;
			initialImageBaseSet = true;
			preferredImageBaseDesc = i.segname;
		}
		else if (i.vmaddr < initialImageBase)
		{
			initialImageBase = i.vmaddr;
			preferredImageBaseDesc = i.segname;
		}
	}

	SetOriginalImageBase(initialImageBase);
	uint64_t preferredImageBase = initialImageBase;
	if (settings)
	{
		if (settings->Contains("loader.imageBase"))
			preferredImageBase = settings->Get<uint64_t>("loader.imageBase", this);

		if (settings->Contains("loader.platform"))
		{
			Ref<Platform> platform = Platform::GetByName(settings->Get<string>("loader.platform", this));
			if (platform)
			{
				m_plat = platform;
				m_arch = platform->GetArchitecture();
			}
		}
	}

	m_imageBaseAdjustment = 0;
	if (!initialImageBase)
		m_imageBaseAdjustment = preferredImageBase;
	else if (initialImageBase <= preferredImageBase)
		m_imageBaseAdjustment = preferredImageBase - initialImageBase;
	else
		m_imageBaseAdjustment = -(int64_t)(initialImageBase - preferredImageBase);

	// Add Mach-O file header type info
	EnumerationBuilder cpuTypeBuilder;
	cpuTypeBuilder.AddMemberWithValue("CPU_TYPE_ANY", MACHO_CPU_TYPE_ANY);
	cpuTypeBuilder.AddMemberWithValue("CPU_TYPE_VAX", MACHO_CPU_TYPE_VAX);
	cpuTypeBuilder.AddMemberWithValue("CPU_TYPE_MC680x0", MACHO_CPU_TYPE_MC680x0);
	cpuTypeBuilder.AddMemberWithValue("CPU_TYPE_X86", MACHO_CPU_TYPE_X86);
	cpuTypeBuilder.AddMemberWithValue("CPU_TYPE_X86_64", MACHO_CPU_TYPE_X86_64);
	cpuTypeBuilder.AddMemberWithValue("CPU_TYPE_MIPS", MACHO_CPU_TYPE_MIPS);
	cpuTypeBuilder.AddMemberWithValue("CPU_TYPE_MC98000", MACHO_CPU_TYPE_MC98000);
	cpuTypeBuilder.AddMemberWithValue("CPU_TYPE_HPPA", MACHO_CPU_TYPE_HPPA);
	cpuTypeBuilder.AddMemberWithValue("CPU_TYPE_ARM", MACHO_CPU_TYPE_ARM);
	cpuTypeBuilder.AddMemberWithValue("CPU_TYPE_ARM64", MACHO_CPU_TYPE_ARM64);
	cpuTypeBuilder.AddMemberWithValue("CPU_TYPE_ARM64_32", MACHO_CPU_TYPE_ARM64_32);
	cpuTypeBuilder.AddMemberWithValue("CPU_TYPE_MC88000", MACHO_CPU_TYPE_MC88000);
	cpuTypeBuilder.AddMemberWithValue("CPU_TYPE_SPARC", MACHO_CPU_TYPE_SPARC);
	cpuTypeBuilder.AddMemberWithValue("CPU_TYPE_I860", MACHO_CPU_TYPE_I860);
	cpuTypeBuilder.AddMemberWithValue("CPU_TYPE_ALPHA", MACHO_CPU_TYPE_ALPHA);
	cpuTypeBuilder.AddMemberWithValue("CPU_TYPE_POWERPC", MACHO_CPU_TYPE_POWERPC);
	cpuTypeBuilder.AddMemberWithValue("CPU_TYPE_POWERPC64", MACHO_CPU_TYPE_POWERPC64);
	Ref<Enumeration> cpuTypeEnum = cpuTypeBuilder.Finalize();

	Ref<Type> cpuTypeEnumType = Type::EnumerationType(nullptr, cpuTypeEnum, 4, false);
	string cpuTypeEnumName = "cpu_type_t";
	string cpuTypeEnumId = Type::GenerateAutoTypeId("macho", cpuTypeEnumName);
	m_typeNames.cpuTypeEnumQualName = DefineType(cpuTypeEnumId, cpuTypeEnumName, cpuTypeEnumType);

	EnumerationBuilder fileTypeBuilder;
	fileTypeBuilder.AddMemberWithValue("MH_OBJECT", MH_OBJECT);
	fileTypeBuilder.AddMemberWithValue("MH_EXECUTE", MH_EXECUTE);
	fileTypeBuilder.AddMemberWithValue("MH_FVMLIB", MH_FVMLIB);
	fileTypeBuilder.AddMemberWithValue("MH_CORE", MH_CORE);
	fileTypeBuilder.AddMemberWithValue("MH_PRELOAD", MH_PRELOAD);
	fileTypeBuilder.AddMemberWithValue("MH_DYLIB", MH_DYLIB);
	fileTypeBuilder.AddMemberWithValue("MH_DYLINKER", MH_DYLINKER);
	fileTypeBuilder.AddMemberWithValue("MH_BUNDLE", MH_BUNDLE);
	fileTypeBuilder.AddMemberWithValue("MH_DYLIB_STUB", MH_DYLIB_STUB);
	fileTypeBuilder.AddMemberWithValue("MH_DSYM", MH_DSYM);
	fileTypeBuilder.AddMemberWithValue("MH_KEXT_BUNDLE", MH_KEXT_BUNDLE);
	fileTypeBuilder.AddMemberWithValue("MH_FILESET", MH_FILESET);
	Ref<Enumeration> fileTypeEnum = fileTypeBuilder.Finalize();

	Ref<Type> fileTypeEnumType = Type::EnumerationType(nullptr, fileTypeEnum, 4, false);
	string fileTypeEnumName = "file_type_t";
	string fileTypeEnumId = Type::GenerateAutoTypeId("macho", fileTypeEnumName);
	m_typeNames.fileTypeEnumQualName = DefineType(fileTypeEnumId, fileTypeEnumName, fileTypeEnumType);

	EnumerationBuilder flagsTypeBuilder;
	flagsTypeBuilder.AddMemberWithValue("MH_NOUNDEFS", MH_NOUNDEFS);
	flagsTypeBuilder.AddMemberWithValue("MH_INCRLINK", MH_INCRLINK);
	flagsTypeBuilder.AddMemberWithValue("MH_DYLDLINK", MH_DYLDLINK);
	flagsTypeBuilder.AddMemberWithValue("MH_BINDATLOAD", MH_BINDATLOAD);
	flagsTypeBuilder.AddMemberWithValue("MH_PREBOUND", MH_PREBOUND);
	flagsTypeBuilder.AddMemberWithValue("MH_SPLIT_SEGS", MH_SPLIT_SEGS);
	flagsTypeBuilder.AddMemberWithValue("MH_LAZY_INIT", MH_LAZY_INIT);
	flagsTypeBuilder.AddMemberWithValue("MH_TWOLEVEL", MH_TWOLEVEL);
	flagsTypeBuilder.AddMemberWithValue("MH_FORCE_FLAT", MH_FORCE_FLAT);
	flagsTypeBuilder.AddMemberWithValue("MH_NOMULTIDEFS", MH_NOMULTIDEFS);
	flagsTypeBuilder.AddMemberWithValue("MH_NOFIXPREBINDING", MH_NOFIXPREBINDING);
	flagsTypeBuilder.AddMemberWithValue("MH_PREBINDABLE", MH_PREBINDABLE);
	flagsTypeBuilder.AddMemberWithValue("MH_ALLMODSBOUND", MH_ALLMODSBOUND);
	flagsTypeBuilder.AddMemberWithValue("MH_SUBSECTIONS_VIA_SYMBOLS", MH_SUBSECTIONS_VIA_SYMBOLS);
	flagsTypeBuilder.AddMemberWithValue("MH_CANONICAL", MH_CANONICAL);
	flagsTypeBuilder.AddMemberWithValue("MH_WEAK_DEFINES", MH_WEAK_DEFINES);
	flagsTypeBuilder.AddMemberWithValue("MH_BINDS_TO_WEAK", MH_BINDS_TO_WEAK);
	flagsTypeBuilder.AddMemberWithValue("MH_ALLOW_STACK_EXECUTION", MH_ALLOW_STACK_EXECUTION);
	flagsTypeBuilder.AddMemberWithValue("MH_ROOT_SAFE", MH_ROOT_SAFE);
	flagsTypeBuilder.AddMemberWithValue("MH_SETUID_SAFE", MH_SETUID_SAFE);
	flagsTypeBuilder.AddMemberWithValue("MH_NO_REEXPORTED_DYLIBS", MH_NO_REEXPORTED_DYLIBS);
	flagsTypeBuilder.AddMemberWithValue("MH_PIE", MH_PIE);
	flagsTypeBuilder.AddMemberWithValue("MH_DEAD_STRIPPABLE_DYLIB", MH_DEAD_STRIPPABLE_DYLIB);
	flagsTypeBuilder.AddMemberWithValue("MH_HAS_TLV_DESCRIPTORS", MH_HAS_TLV_DESCRIPTORS);
	flagsTypeBuilder.AddMemberWithValue("MH_NO_HEAP_EXECUTION", MH_NO_HEAP_EXECUTION);
	flagsTypeBuilder.AddMemberWithValue("MH_APP_EXTENSION_SAFE", _MH_APP_EXTENSION_SAFE);
	flagsTypeBuilder.AddMemberWithValue("MH_NLIST_OUTOFSYNC_WITH_DYLDINFO", _MH_NLIST_OUTOFSYNC_WITH_DYLDINFO);
	flagsTypeBuilder.AddMemberWithValue("MH_SIM_SUPPORT", _MH_SIM_SUPPORT);
	flagsTypeBuilder.AddMemberWithValue("MH_DYLIB_IN_CACHE", _MH_DYLIB_IN_CACHE);
	Ref<Enumeration> flagsTypeEnum = flagsTypeBuilder.Finalize();

	Ref<Type> flagsTypeEnumType = Type::EnumerationType(nullptr, flagsTypeEnum, 4, false);
	string flagsTypeEnumName = "flags_type_t";
	string flagsTypeEnumId = Type::GenerateAutoTypeId("macho", flagsTypeEnumName);
	m_typeNames.flagsTypeEnumQualName = DefineType(flagsTypeEnumId, flagsTypeEnumName, flagsTypeEnumType);

	StructureBuilder machoHeaderBuilder;
	machoHeaderBuilder.AddMember(Type::IntegerType(4, false), "magic");
	machoHeaderBuilder.AddMember(Type::NamedType(this, m_typeNames.cpuTypeEnumQualName), "cputype");
	machoHeaderBuilder.AddMember(Type::IntegerType(4, false), "cpusubtype");
	machoHeaderBuilder.AddMember(Type::NamedType(this, m_typeNames.fileTypeEnumQualName), "filetype");
	machoHeaderBuilder.AddMember(Type::IntegerType(4, false), "ncmds");
	machoHeaderBuilder.AddMember(Type::IntegerType(4, false), "sizeofcmds");
	machoHeaderBuilder.AddMember(Type::NamedType(this, m_typeNames.flagsTypeEnumQualName), "flags");
	if (m_addressSize == 8)
		machoHeaderBuilder.AddMember(Type::IntegerType(4, false), "reserved");
	Ref<Structure> machoHeaderStruct = machoHeaderBuilder.Finalize();
	QualifiedName headerName = (m_addressSize == 8) ? string("mach_header_64") : string("mach_header");

	string headerTypeId = Type::GenerateAutoTypeId("macho", headerName);
	Ref<Type> machoHeaderType = Type::StructureType(machoHeaderStruct);
	m_typeNames.headerQualName = DefineType(headerTypeId, headerName, machoHeaderType);

	EnumerationBuilder cmdTypeBuilder;
	cmdTypeBuilder.AddMemberWithValue("LC_REQ_DYLD", LC_REQ_DYLD);
	cmdTypeBuilder.AddMemberWithValue("LC_SEGMENT", LC_SEGMENT);
	cmdTypeBuilder.AddMemberWithValue("LC_SYMTAB", LC_SYMTAB);
	cmdTypeBuilder.AddMemberWithValue("LC_SYMSEG",LC_SYMSEG);
	cmdTypeBuilder.AddMemberWithValue("LC_THREAD", LC_THREAD);
	cmdTypeBuilder.AddMemberWithValue("LC_UNIXTHREAD", LC_UNIXTHREAD);
	cmdTypeBuilder.AddMemberWithValue("LC_LOADFVMLIB", LC_LOADFVMLIB);
	cmdTypeBuilder.AddMemberWithValue("LC_IDFVMLIB", LC_IDFVMLIB);
	cmdTypeBuilder.AddMemberWithValue("LC_IDENT", LC_IDENT);
	cmdTypeBuilder.AddMemberWithValue("LC_FVMFILE", LC_FVMFILE);
	cmdTypeBuilder.AddMemberWithValue("LC_PREPAGE", LC_PREPAGE);
	cmdTypeBuilder.AddMemberWithValue("LC_DYSYMTAB", LC_DYSYMTAB);
	cmdTypeBuilder.AddMemberWithValue("LC_LOAD_DYLIB", LC_LOAD_DYLIB);
	cmdTypeBuilder.AddMemberWithValue("LC_ID_DYLIB", LC_ID_DYLIB);
	cmdTypeBuilder.AddMemberWithValue("LC_LOAD_DYLINKER", LC_LOAD_DYLINKER);
	cmdTypeBuilder.AddMemberWithValue("LC_ID_DYLINKER", LC_ID_DYLINKER);
	cmdTypeBuilder.AddMemberWithValue("LC_PREBOUND_DYLIB", LC_PREBOUND_DYLIB);
	cmdTypeBuilder.AddMemberWithValue("LC_ROUTINES", LC_ROUTINES);
	cmdTypeBuilder.AddMemberWithValue("LC_SUB_FRAMEWORK", LC_SUB_FRAMEWORK);
	cmdTypeBuilder.AddMemberWithValue("LC_SUB_UMBRELLA", LC_SUB_UMBRELLA);
	cmdTypeBuilder.AddMemberWithValue("LC_SUB_CLIENT", LC_SUB_CLIENT);
	cmdTypeBuilder.AddMemberWithValue("LC_SUB_LIBRARY", LC_SUB_LIBRARY);
	cmdTypeBuilder.AddMemberWithValue("LC_TWOLEVEL_HINTS", LC_TWOLEVEL_HINTS);
	cmdTypeBuilder.AddMemberWithValue("LC_PREBIND_CKSUM", LC_PREBIND_CKSUM);
	cmdTypeBuilder.AddMemberWithValue("LC_LOAD_WEAK_DYLIB", LC_LOAD_WEAK_DYLIB);//       (0x18 | LC_REQ_DYLD)
	cmdTypeBuilder.AddMemberWithValue("LC_SEGMENT_64", LC_SEGMENT_64);
	cmdTypeBuilder.AddMemberWithValue("LC_ROUTINES_64", LC_ROUTINES_64);
	cmdTypeBuilder.AddMemberWithValue("LC_UUID", LC_UUID);
	cmdTypeBuilder.AddMemberWithValue("LC_RPATH", LC_RPATH);//                 (0x1c | LC_REQ_DYLD)
	cmdTypeBuilder.AddMemberWithValue("LC_CODE_SIGNATURE", LC_CODE_SIGNATURE);
	cmdTypeBuilder.AddMemberWithValue("LC_SEGMENT_SPLIT_INFO", LC_SEGMENT_SPLIT_INFO);
	cmdTypeBuilder.AddMemberWithValue("LC_REEXPORT_DYLIB", LC_REEXPORT_DYLIB);//        (0x1f | LC_REQ_DYLD)
	cmdTypeBuilder.AddMemberWithValue("LC_LAZY_LOAD_DYLIB", LC_LAZY_LOAD_DYLIB);
	cmdTypeBuilder.AddMemberWithValue("LC_ENCRYPTION_INFO", LC_ENCRYPTION_INFO);
	cmdTypeBuilder.AddMemberWithValue("LC_DYLD_INFO", LC_DYLD_INFO);
	cmdTypeBuilder.AddMemberWithValue("LC_DYLD_INFO_ONLY", LC_DYLD_INFO_ONLY);//        (0x22 | LC_REQ_DYLD)
	cmdTypeBuilder.AddMemberWithValue("LC_LOAD_UPWARD_DYLIB", LC_LOAD_UPWARD_DYLIB);//     (0x23 | LC_REQ_DYLD)
	cmdTypeBuilder.AddMemberWithValue("LC_VERSION_MIN_MACOSX", LC_VERSION_MIN_MACOSX);
	cmdTypeBuilder.AddMemberWithValue("LC_VERSION_MIN_IPHONEOS", LC_VERSION_MIN_IPHONEOS);
	cmdTypeBuilder.AddMemberWithValue("LC_FUNCTION_STARTS", LC_FUNCTION_STARTS);
	cmdTypeBuilder.AddMemberWithValue("LC_DYLD_ENVIRONMENT", LC_DYLD_ENVIRONMENT);
	cmdTypeBuilder.AddMemberWithValue("LC_MAIN", LC_MAIN);//                  (0x28 | LC_REQ_DYLD)
	cmdTypeBuilder.AddMemberWithValue("LC_DATA_IN_CODE", LC_DATA_IN_CODE);
	cmdTypeBuilder.AddMemberWithValue("LC_SOURCE_VERSION", LC_SOURCE_VERSION);
	cmdTypeBuilder.AddMemberWithValue("LC_DYLIB_CODE_SIGN_DRS", LC_DYLIB_CODE_SIGN_DRS);
	cmdTypeBuilder.AddMemberWithValue("LC_ENCRYPTION_INFO_64", _LC_ENCRYPTION_INFO_64);
	cmdTypeBuilder.AddMemberWithValue("LC_LINKER_OPTION", _LC_LINKER_OPTION);
	cmdTypeBuilder.AddMemberWithValue("LC_LINKER_OPTIMIZATION_HINT", _LC_LINKER_OPTIMIZATION_HINT);
	cmdTypeBuilder.AddMemberWithValue("LC_VERSION_MIN_TVOS", _LC_VERSION_MIN_TVOS);
	cmdTypeBuilder.AddMemberWithValue("LC_VERSION_MIN_WATCHOS", LC_VERSION_MIN_WATCHOS);
	cmdTypeBuilder.AddMemberWithValue("LC_NOTE", LC_NOTE);
	cmdTypeBuilder.AddMemberWithValue("LC_BUILD_VERSION", LC_BUILD_VERSION);
	cmdTypeBuilder.AddMemberWithValue("LC_DYLD_EXPORTS_TRIE", LC_DYLD_EXPORTS_TRIE);
	cmdTypeBuilder.AddMemberWithValue("LC_DYLD_CHAINED_FIXUPS", LC_DYLD_CHAINED_FIXUPS);
	cmdTypeBuilder.AddMemberWithValue("LC_FILESET_ENTRY", LC_FILESET_ENTRY);
	Ref<Enumeration> cmdTypeEnum = cmdTypeBuilder.Finalize();

	Ref<Type> cmdTypeEnumType = Type::EnumerationType(nullptr, cmdTypeEnum, 4, false);
	string cmdTypeEnumName = "load_command_type_t";
	string cmdTypeEnumId = Type::GenerateAutoTypeId("macho", cmdTypeEnumName);
	m_typeNames.cmdTypeEnumQualName = DefineType(cmdTypeEnumId, cmdTypeEnumName, cmdTypeEnumType);

	StructureBuilder loadCommandBuilder;
	loadCommandBuilder.AddMember(Type::NamedType(this, m_typeNames.cmdTypeEnumQualName), "cmd");
	loadCommandBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	Ref<Structure> loadCommandStruct = loadCommandBuilder.Finalize();
	QualifiedName loadCommandName = string("load_command");
	string loadCommandTypeId = Type::GenerateAutoTypeId("macho", loadCommandName);
	Ref<Type> loadCommandType = Type::StructureType(loadCommandStruct);
	m_typeNames.loadCommandQualName = DefineType(loadCommandTypeId, loadCommandName, loadCommandType);

	EnumerationBuilder protTypeBuilder;
	protTypeBuilder.AddMemberWithValue("VM_PROT_NONE", MACHO_VM_PROT_NONE);
	protTypeBuilder.AddMemberWithValue("VM_PROT_READ", MACHO_VM_PROT_READ);
	protTypeBuilder.AddMemberWithValue("VM_PROT_WRITE", MACHO_VM_PROT_WRITE);
	protTypeBuilder.AddMemberWithValue("VM_PROT_EXECUTE", MACHO_VM_PROT_EXECUTE);
	// protTypeBuilder.AddMemberWithValue("VM_PROT_DEFAULT", MACHO_VM_PROT_DEFAULT);
	// protTypeBuilder.AddMemberWithValue("VM_PROT_ALL", MACHO_VM_PROT_ALL);
	protTypeBuilder.AddMemberWithValue("VM_PROT_NO_CHANGE", MACHO_VM_PROT_NO_CHANGE);
	protTypeBuilder.AddMemberWithValue("VM_PROT_COPY_OR_WANTS_COPY", MACHO_VM_PROT_COPY);
	//protTypeBuilder.AddMemberWithValue("VM_PROT_WANTS_COPY", MACHO_VM_PROT_WANTS_COPY);
	Ref<Enumeration> protTypeEnum = protTypeBuilder.Finalize();

	Ref<Type> protTypeEnumType = Type::EnumerationType(nullptr, protTypeEnum, 4, false);
	string protTypeEnumName = "vm_prot_t";
	string protTypeEnumId = Type::GenerateAutoTypeId("macho", protTypeEnumName);
	m_typeNames.protTypeEnumQualName = DefineType(protTypeEnumId, protTypeEnumName, protTypeEnumType);

	EnumerationBuilder segFlagsTypeBuilder;
	segFlagsTypeBuilder.AddMemberWithValue("SG_HIGHVM", SG_HIGHVM);
	segFlagsTypeBuilder.AddMemberWithValue("SG_FVMLIB", SG_FVMLIB);
	segFlagsTypeBuilder.AddMemberWithValue("SG_NORELOC", SG_NORELOC);
	segFlagsTypeBuilder.AddMemberWithValue("SG_PROTECTED_VERSION_1", SG_PROTECTED_VERSION_1);
	Ref<Enumeration> segFlagsTypeEnum = segFlagsTypeBuilder.Finalize();

	Ref<Type> segFlagsTypeEnumType = Type::EnumerationType(nullptr, segFlagsTypeEnum, 4, false);
	string segFlagsTypeEnumName = "sg_flags_t";
	string segFlagsTypeEnumId = Type::GenerateAutoTypeId("macho", segFlagsTypeEnumName);
	m_typeNames.segFlagsTypeEnumQualName = DefineType(segFlagsTypeEnumId, segFlagsTypeEnumName, segFlagsTypeEnumType);

	StructureBuilder loadSegmentCommandBuilder;
	loadSegmentCommandBuilder.AddMember(Type::NamedType(this, m_typeNames.cmdTypeEnumQualName), "cmd");
	loadSegmentCommandBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	loadSegmentCommandBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 16), "segname");
	loadSegmentCommandBuilder.AddMember(Type::IntegerType(4, false), "vmaddr");
	loadSegmentCommandBuilder.AddMember(Type::IntegerType(4, false), "vmsize");
	loadSegmentCommandBuilder.AddMember(Type::IntegerType(4, false), "fileoff");
	loadSegmentCommandBuilder.AddMember(Type::IntegerType(4, false), "filesize");
	loadSegmentCommandBuilder.AddMember(Type::NamedType(this, m_typeNames.protTypeEnumQualName), "maxprot");
	loadSegmentCommandBuilder.AddMember(Type::NamedType(this, m_typeNames.protTypeEnumQualName), "initprot");
	loadSegmentCommandBuilder.AddMember(Type::IntegerType(4, false), "nsects");
	loadSegmentCommandBuilder.AddMember(Type::NamedType(this, m_typeNames.segFlagsTypeEnumQualName), "flags");
	Ref<Structure> loadSegmentCommandStruct = loadSegmentCommandBuilder.Finalize();
	QualifiedName loadSegmentCommandName = string("segment_command");
	string loadSegmentCommandTypeId = Type::GenerateAutoTypeId("macho", loadSegmentCommandName);
	Ref<Type> loadSegmentCommandType = Type::StructureType(loadSegmentCommandStruct);
	m_typeNames.loadSegmentCommandQualName = DefineType(loadSegmentCommandTypeId, loadSegmentCommandName, loadSegmentCommandType);

	StructureBuilder loadSegmentCommand64Builder;
	loadSegmentCommand64Builder.AddMember(Type::NamedType(this, m_typeNames.cmdTypeEnumQualName), "cmd");
	loadSegmentCommand64Builder.AddMember(Type::IntegerType(4, false), "cmdsize");
	loadSegmentCommand64Builder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 16), "segname");
	loadSegmentCommand64Builder.AddMember(Type::IntegerType(8, false), "vmaddr");
	loadSegmentCommand64Builder.AddMember(Type::IntegerType(8, false), "vmsize");
	loadSegmentCommand64Builder.AddMember(Type::IntegerType(8, false), "fileoff");
	loadSegmentCommand64Builder.AddMember(Type::IntegerType(8, false), "filesize");
	loadSegmentCommand64Builder.AddMember(Type::NamedType(this, m_typeNames.protTypeEnumQualName), "maxprot");
	loadSegmentCommand64Builder.AddMember(Type::NamedType(this, m_typeNames.protTypeEnumQualName), "initprot");
	loadSegmentCommand64Builder.AddMember(Type::IntegerType(4, false), "nsects");
	loadSegmentCommand64Builder.AddMember(Type::NamedType(this, m_typeNames.segFlagsTypeEnumQualName), "flags");
	Ref<Structure> loadSegmentCommand64Struct = loadSegmentCommand64Builder.Finalize();
	QualifiedName loadSegment64CommandName = string("segment_command_64");
	string loadSegment64CommandTypeId = Type::GenerateAutoTypeId("macho", loadSegment64CommandName);
	Ref<Type> loadSegment64CommandType = Type::StructureType(loadSegmentCommand64Struct);
	m_typeNames.loadSegment64CommandQualName = DefineType(loadSegment64CommandTypeId, loadSegment64CommandName, loadSegment64CommandType);

	StructureBuilder sectionBuilder;
	sectionBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 16), "sectname");
	sectionBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 16), "segname");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "addr");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "size");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "offset");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "align");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "reloff");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "nreloc");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "flags");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "reserved1");
	sectionBuilder.AddMember(Type::IntegerType(4, false), "reserved2");
	Ref<Structure> sectionStruct = sectionBuilder.Finalize();
	QualifiedName sectionName = string("section");
	string sectionTypeId = Type::GenerateAutoTypeId("macho", sectionName);
	Ref<Type> sectionType = Type::StructureType(sectionStruct);
	m_typeNames.sectionQualName = DefineType(sectionTypeId, sectionName, sectionType);

	StructureBuilder section64Builder;
	section64Builder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 16), "sectname");
	section64Builder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 16), "segname");
	section64Builder.AddMember(Type::IntegerType(8, false), "addr");
	section64Builder.AddMember(Type::IntegerType(8, false), "size");
	section64Builder.AddMember(Type::IntegerType(4, false), "offset");
	section64Builder.AddMember(Type::IntegerType(4, false), "align");
	section64Builder.AddMember(Type::IntegerType(4, false), "reloff");
	section64Builder.AddMember(Type::IntegerType(4, false), "nreloc");
	section64Builder.AddMember(Type::IntegerType(4, false), "flags");
	section64Builder.AddMember(Type::IntegerType(4, false), "reserved1");
	section64Builder.AddMember(Type::IntegerType(4, false), "reserved2");
	section64Builder.AddMember(Type::IntegerType(4, false), "reserved3");
	Ref<Structure> section64Struct = section64Builder.Finalize();
	QualifiedName section64Name = string("section_64");
	string section64TypeId = Type::GenerateAutoTypeId("macho", section64Name);
	Ref<Type> section64Type = Type::StructureType(section64Struct);
	m_typeNames.section64QualName = DefineType(section64TypeId, section64Name, section64Type);

	StructureBuilder symtabBuilder;
	symtabBuilder.AddMember(Type::NamedType(this, m_typeNames.cmdTypeEnumQualName), "cmd");
	symtabBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	symtabBuilder.AddMember(Type::IntegerType(4, false), "symoff");
	symtabBuilder.AddMember(Type::IntegerType(4, false), "nsyms");
	symtabBuilder.AddMember(Type::IntegerType(4, false), "stroff");
	symtabBuilder.AddMember(Type::IntegerType(4, false), "strsize");
	Ref<Structure> symtabStruct = symtabBuilder.Finalize();
	QualifiedName symtabName = string("symtab");
	string symtabTypeId = Type::GenerateAutoTypeId("macho", symtabName);
	Ref<Type> symtabType = Type::StructureType(symtabStruct);
	m_typeNames.symtabQualName = DefineType(symtabTypeId, symtabName, symtabType);

	StructureBuilder dynsymtabBuilder;
	dynsymtabBuilder.AddMember(Type::NamedType(this, m_typeNames.cmdTypeEnumQualName), "cmd");
	dynsymtabBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	dynsymtabBuilder.AddMember(Type::IntegerType(4, false), "ilocalsym");
	dynsymtabBuilder.AddMember(Type::IntegerType(4, false), "nlocalsym");
	dynsymtabBuilder.AddMember(Type::IntegerType(4, false), "iextdefsym");
	dynsymtabBuilder.AddMember(Type::IntegerType(4, false), "nextdefsym");
	dynsymtabBuilder.AddMember(Type::IntegerType(4, false), "iundefsym");
	dynsymtabBuilder.AddMember(Type::IntegerType(4, false), "nundefsym");
	dynsymtabBuilder.AddMember(Type::IntegerType(4, false), "tocoff");
	dynsymtabBuilder.AddMember(Type::IntegerType(4, false), "ntoc");
	dynsymtabBuilder.AddMember(Type::IntegerType(4, false), "modtaboff");
	dynsymtabBuilder.AddMember(Type::IntegerType(4, false), "nmodtab");
	dynsymtabBuilder.AddMember(Type::IntegerType(4, false), "extrefsymoff");
	dynsymtabBuilder.AddMember(Type::IntegerType(4, false), "nextrefsyms");
	dynsymtabBuilder.AddMember(Type::IntegerType(4, false), "indirectsymoff");
	dynsymtabBuilder.AddMember(Type::IntegerType(4, false), "nindirectsyms");
	dynsymtabBuilder.AddMember(Type::IntegerType(4, false), "extreloff");
	dynsymtabBuilder.AddMember(Type::IntegerType(4, false), "nextrel");
	dynsymtabBuilder.AddMember(Type::IntegerType(4, false), "locreloff");
	dynsymtabBuilder.AddMember(Type::IntegerType(4, false), "nlocrel");
	Ref<Structure> dynsymtabStruct = dynsymtabBuilder.Finalize();
	QualifiedName dynsymtabName = string("dynsymtab");
	string dynsymtabTypeId = Type::GenerateAutoTypeId("macho", dynsymtabName);
	Ref<Type> dynsymtabType = Type::StructureType(dynsymtabStruct);
	m_typeNames.dynsymtabQualName = DefineType(dynsymtabTypeId, dynsymtabName, dynsymtabType);

	StructureBuilder uuidBuilder;
	uuidBuilder.AddMember(Type::NamedType(this, m_typeNames.cmdTypeEnumQualName), "cmd");
	uuidBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	uuidBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, false), 16), "uuid");
	Ref<Structure> uuidStruct = uuidBuilder.Finalize();
	QualifiedName uuidName = string("uuid");
	string uuidTypeId = Type::GenerateAutoTypeId("macho", uuidName);
	Ref<Type> uuidType = Type::StructureType(uuidStruct);
	m_typeNames.uuidQualName = DefineType(uuidTypeId, uuidName, uuidType);

	StructureBuilder linkeditDataBuilder;
	linkeditDataBuilder.AddMember(Type::NamedType(this, m_typeNames.cmdTypeEnumQualName), "cmd");
	linkeditDataBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	linkeditDataBuilder.AddMember(Type::IntegerType(4, false), "dataoff");
	linkeditDataBuilder.AddMember(Type::IntegerType(4, false), "datasize");
	Ref<Structure> linkeditDataStruct = linkeditDataBuilder.Finalize();
	QualifiedName linkeditDataName = string("linkedit_data");
	string linkeditDataTypeId = Type::GenerateAutoTypeId("macho", linkeditDataName);
	Ref<Type> linkeditDataType = Type::StructureType(linkeditDataStruct);
	m_typeNames.linkeditDataQualName = DefineType(linkeditDataTypeId, linkeditDataName, linkeditDataType);

	StructureBuilder encryptionInfoBuilder;
	encryptionInfoBuilder.AddMember(Type::NamedType(this, m_typeNames.cmdTypeEnumQualName), "cmd");
	encryptionInfoBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	encryptionInfoBuilder.AddMember(Type::IntegerType(4, false), "cryptoff");
	encryptionInfoBuilder.AddMember(Type::IntegerType(4, false), "cryptsize");
	encryptionInfoBuilder.AddMember(Type::IntegerType(4, false), "cryptid");
	Ref<Structure> encryptionInfoStruct = encryptionInfoBuilder.Finalize();
	QualifiedName encryptionInfoName = string("encryption_info");
	string encryptionInfoTypeId = Type::GenerateAutoTypeId("macho", encryptionInfoName);
	Ref<Type> encryptionInfoType = Type::StructureType(encryptionInfoStruct);
	m_typeNames.encryptionInfoQualName = DefineType(encryptionInfoTypeId, encryptionInfoName, encryptionInfoType);

	StructureBuilder versionMinBuilder;
	versionMinBuilder.AddMember(Type::NamedType(this, m_typeNames.cmdTypeEnumQualName), "cmd");
	versionMinBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	versionMinBuilder.AddMember(Type::IntegerType(4, false), "version");
	versionMinBuilder.AddMember(Type::IntegerType(4, false), "sdk");
	Ref<Structure> versionMinStruct = versionMinBuilder.Finalize();
	QualifiedName versionMinName = string("version_min");
	string versionMinTypeId = Type::GenerateAutoTypeId("macho", versionMinName);
	Ref<Type> versionMinType = Type::StructureType(versionMinStruct);
	m_typeNames.versionMinQualName = DefineType(versionMinTypeId, versionMinName, versionMinType);

	StructureBuilder dyldInfoBuilder;
	dyldInfoBuilder.AddMember(Type::NamedType(this, m_typeNames.cmdTypeEnumQualName), "cmd");
	dyldInfoBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	dyldInfoBuilder.AddMember(Type::IntegerType(4, false), "rebase_off");
	dyldInfoBuilder.AddMember(Type::IntegerType(4, false), "rebase_size");
	dyldInfoBuilder.AddMember(Type::IntegerType(4, false), "bind_off");
	dyldInfoBuilder.AddMember(Type::IntegerType(4, false), "bind_size");
	dyldInfoBuilder.AddMember(Type::IntegerType(4, false), "weak_bind_off");
	dyldInfoBuilder.AddMember(Type::IntegerType(4, false), "weak_bind_size");
	dyldInfoBuilder.AddMember(Type::IntegerType(4, false), "lazy_bind_off");
	dyldInfoBuilder.AddMember(Type::IntegerType(4, false), "lazy_bind_size");
	dyldInfoBuilder.AddMember(Type::IntegerType(4, false), "export_off");
	dyldInfoBuilder.AddMember(Type::IntegerType(4, false), "export_size");
	Ref<Structure> dyldInfoStruct = dyldInfoBuilder.Finalize();
	QualifiedName dyldInfoName = string("dyld_info");
	string dyldInfoTypeId = Type::GenerateAutoTypeId("macho", dyldInfoName);
	Ref<Type> dyldInfoType = Type::StructureType(dyldInfoStruct);
	m_typeNames.dyldInfoQualName = DefineType(dyldInfoTypeId, dyldInfoName, dyldInfoType);

	StructureBuilder dylibBuilder;
	dylibBuilder.AddMember(Type::IntegerType(4, false), "name");
	dylibBuilder.AddMember(Type::IntegerType(4, false), "timestamp");
	dylibBuilder.AddMember(Type::IntegerType(4, false), "current_version");
	dylibBuilder.AddMember(Type::IntegerType(4, false), "compatibility_version");
	Ref<Structure> dylibStruct = dylibBuilder.Finalize();
	QualifiedName dylibName = string("dylib");
	string dylibTypeId = Type::GenerateAutoTypeId("macho", dylibName);
	Ref<Type> dylibType = Type::StructureType(dylibStruct);
	m_typeNames.dylibQualName = DefineType(dylibTypeId, dylibName, dylibType);

	StructureBuilder dylibCommandBuilder;
	dylibCommandBuilder.AddMember(Type::NamedType(this, m_typeNames.cmdTypeEnumQualName), "cmd");
	dylibCommandBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	dylibCommandBuilder.AddMember(Type::NamedType(this, m_typeNames.dylibQualName), "dylib");
	Ref<Structure> dylibCommandStruct = dylibCommandBuilder.Finalize();
	QualifiedName dylibCommandName = string("dylib_command");
	string dylibCommandTypeId = Type::GenerateAutoTypeId("macho", dylibCommandName);
	Ref<Type> dylibCommandType = Type::StructureType(dylibCommandStruct);
	m_typeNames.dylibCommandQualName = DefineType(dylibCommandTypeId, dylibCommandName, dylibCommandType);

	StructureBuilder filesetEntryCommandBuilder;
	filesetEntryCommandBuilder.AddMember(Type::NamedType(this, m_typeNames.cmdTypeEnumQualName), "cmd");
	filesetEntryCommandBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	filesetEntryCommandBuilder.AddMember(Type::IntegerType(8, false), "vmaddr");
	filesetEntryCommandBuilder.AddMember(Type::IntegerType(8, false), "fileoff");
	filesetEntryCommandBuilder.AddMember(Type::IntegerType(4, false), "entry_id");
	filesetEntryCommandBuilder.AddMember(Type::IntegerType(4, false), "reserved");
	Ref<Structure> filesetEntryCommandStruct = filesetEntryCommandBuilder.Finalize();
	QualifiedName filesetEntryCommandName = string("fileset_entry_command");
	string filesetEntryCommandTypeId = Type::GenerateAutoTypeId("macho", filesetEntryCommandName);
	Ref<Type> filesetEntryCommandType = Type::StructureType(filesetEntryCommandStruct);
	m_typeNames.filesetEntryCommandQualName = DefineType(filesetEntryCommandTypeId, filesetEntryCommandName, filesetEntryCommandType);

	if (!InitializeHeader(m_header, true, preferredImageBase, preferredImageBaseDesc))
		return false;

	for (auto& it : m_subHeaders)
	{
		if (!InitializeHeader(it.second, false, it.first, ""))
			return false;
	}

	std::chrono::steady_clock::time_point endTime = std::chrono::steady_clock::now();
	double t = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count() / 1000.0;
	m_logger->LogInfo("Mach-O parsing took %.3f seconds\n", t);
	return true;
}


bool MachoView::InitializeHeader(MachOHeader& header, bool isMainHeader, uint64_t preferredImageBase, std::string preferredImageBaseDesc)
{
	Ref<Settings> settings = GetLoadSettings(GetTypeName());

	for (auto& i : header.segments)
		i.vmaddr += m_imageBaseAdjustment;

	for (auto& i : header.sections)
		i.addr += m_imageBaseAdjustment;

	for (auto& i : header.symbolStubSections)
		i.addr += m_imageBaseAdjustment;

	for (auto& i : header.symbolPointerSections)
		i.addr += m_imageBaseAdjustment;

	for (auto& entryPoint : header.entryPoints)
		entryPoint.first += (entryPoint.second ? 0 : m_imageBaseAdjustment);

	if (header.routinesPresent)
		header.routines64.init_address += m_imageBaseAdjustment;

	for (auto& segment : header.segments)
	{
		if ((segment.initprot == MACHO_VM_PROT_NONE) || (!segment.vmsize))
			continue;

		if ((segment.initprot & MACHO_VM_PROT_EXECUTE) == MACHO_VM_PROT_EXECUTE)
		{
			if ((segment.fileoff == (0 + m_universalImageOffset)) && (segment.filesize != 0))
				header.textBase = segment.vmaddr;
			for (auto& entryPoint : header.entryPoints)
			{
				uint64_t val = entryPoint.first + (entryPoint.second ? header.textBase : 0);
				if (find(header.m_entryPoints.begin(), header.m_entryPoints.end(), val) == header.m_entryPoints.end())
					header.m_entryPoints.push_back(val);
			}
		}
	}

	if (!(m_header.ident.filetype == MH_FILESET && isMainHeader)) \
	{
		BeginBulkAddSegments();
		for (auto &segment: header.segments) {
			if ((segment.initprot == MACHO_VM_PROT_NONE) || (!segment.vmsize))
				continue;

			uint32_t flags = 0;
			if (segment.initprot & MACHO_VM_PROT_READ)
				flags |= SegmentReadable;
			if (segment.initprot & MACHO_VM_PROT_WRITE)
				flags |= SegmentWritable;
			if (segment.initprot & MACHO_VM_PROT_EXECUTE)
				flags |= SegmentExecutable;
			if (((segment.initprot & MACHO_VM_PROT_WRITE) == 0) &&
			    ((segment.maxprot & MACHO_VM_PROT_WRITE) == 0))
				flags |= SegmentDenyWrite;
			if (((segment.initprot & MACHO_VM_PROT_EXECUTE) == 0) &&
			    ((segment.maxprot & MACHO_VM_PROT_EXECUTE) == 0))
				flags |= SegmentDenyExecute;

			// if we're positive we have an entry point for some reason, force the segment
			// executable. this helps with kernel images.
			for (auto &entryPoint: header.m_entryPoints)
				if (segment.vmaddr <= entryPoint && (entryPoint < (segment.vmaddr + segment.filesize)))
					flags |= SegmentExecutable;

			AddAutoSegment(segment.vmaddr, segment.vmsize, segment.fileoff, segment.filesize, flags);
		}
		EndBulkAddSegments();

		for (auto& section : header.sections)
		{
			char sectionName[17];
			memcpy(sectionName, section.sectname, sizeof(section.sectname));
			sectionName[16] = 0;
			if (header.identifierPrefix.empty())
				header.sectionNames.push_back(sectionName);
			else
				header.sectionNames.push_back(header.identifierPrefix + "::" + sectionName);
		}

		header.sectionNames = GetUniqueSectionNames(header.sectionNames);
	}

	for (size_t i = 0; i < header.sections.size(); i++)
	{
		if (!header.sections[i].size)
			continue;

		string type;
		BNSectionSemantics semantics = DefaultSectionSemantics;
		switch (header.sections[i].flags & 0xff)
		{
		case S_REGULAR:
			if (header.sections[i].flags & S_ATTR_PURE_INSTRUCTIONS)
			{
				type = "PURE_CODE";
				semantics = ReadOnlyCodeSectionSemantics;
			}
			else if (header.sections[i].flags & S_ATTR_SOME_INSTRUCTIONS)
			{
				type = "CODE";
				semantics = ReadOnlyCodeSectionSemantics;
			}
			else
			{
				type = "REGULAR";
			}
			break;
		case S_ZEROFILL:
			type = "ZEROFILL";
			semantics = ReadWriteDataSectionSemantics;
			break;
		case S_CSTRING_LITERALS:
			type = "CSTRING_LITERALS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_4BYTE_LITERALS:
			type = "4BYTE_LITERALS";
			break;
		case S_8BYTE_LITERALS:
			type = "8BYTE_LITERALS";
			break;
		case S_LITERAL_POINTERS:
			type = "LITERAL_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_NON_LAZY_SYMBOL_POINTERS:
			type = "NON_LAZY_SYMBOL_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_LAZY_SYMBOL_POINTERS:
			type = "LAZY_SYMBOL_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_SYMBOL_STUBS:
			type = "SYMBOL_STUBS";
			semantics = ReadOnlyCodeSectionSemantics;
			break;
		case S_MOD_INIT_FUNC_POINTERS:
			type = "MOD_INIT_FUNC_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_MOD_TERM_FUNC_POINTERS:
			type = "MOD_TERM_FUNC_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_COALESCED:
			type = "COALESCED";
			break;
		case S_GB_ZEROFILL:
			type = "GB_ZEROFILL";
			semantics = ReadWriteDataSectionSemantics;
			break;
		case S_INTERPOSING:
			type = "INTERPOSING";
			break;
		case S_16BYTE_LITERALS:
			type = "16BYTE_LITERALS";
			break;
		case S_DTRACE_DOF:
			type = "DTRACE_DOF";
			break;
		case S_LAZY_DYLIB_SYMBOL_POINTERS:
			type = "LAZY_DYLIB_SYMBOL_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_THREAD_LOCAL_REGULAR:
			type = "THREAD_LOCAL_REGULAR";
			break;
		case S_THREAD_LOCAL_ZEROFILL:
			type = "THREAD_LOCAL_ZEROFILL";
			break;
		case S_THREAD_LOCAL_VARIABLES:
			type = "THREAD_LOCAL_VARIABLES";
			break;
		case S_THREAD_LOCAL_VARIABLE_POINTERS:
			type = "THREAD_LOCAL_VARIABLE_POINTERS";
			break;
		case S_THREAD_LOCAL_INIT_FUNCTION_POINTERS:
			type = "THREAD_LOCAL_INIT_FUNCTION_POINTERS";
			break;
		default:
			type = "UNKNOWN";
			break;
		}
		if (i >= header.sectionNames.size())
			break;
		if (strncmp(header.sections[i].sectname, "__text", sizeof(header.sections[i].sectname)) == 0)
			semantics = ReadOnlyCodeSectionSemantics;
		if (strncmp(header.sections[i].sectname, "__const", sizeof(header.sections[i].sectname)) == 0)
			semantics = ReadOnlyDataSectionSemantics;
		if (strncmp(header.sections[i].sectname, "__data", sizeof(header.sections[i].sectname)) == 0)
			semantics = ReadWriteDataSectionSemantics;
		if (strncmp(header.sections[i].segname, "__DATA_CONST", sizeof(header.sections[i].segname)) == 0)
			semantics = ReadOnlyDataSectionSemantics;
		if (strncmp(header.sections[i].sectname, "__chain_starts", sizeof(header.sections[i].sectname)) == 0
			&& header.sections[i].size < UINT32_MAX)
		{
			header.chainStartsPresent = true;
			header.chainStarts = header.sections[i];
		}

		AddAutoSection(header.sectionNames[i], header.sections[i].addr, header.sections[i].size, semantics, type, header.sections[i].align);
	}
	if (isMainHeader)
	{
		// Validate architecture
		if (!m_arch)
		{
			// Parse only mode returns true, even if no arch support
			if (m_parseOnly)
				return true;

			bool is64Bit;
			string archName = UniversalViewType::ArchitectureToString(m_archId, 0, is64Bit);
			if (!archName.empty())
			{
				#ifdef DEMO_EDITION
				if ((archName == "arm64")			/* MACHO_CPU_TYPE_ARM64 */
					|| (archName == "arm64v8")
					|| (archName == "arm64e")
					|| (archName == "arm64_32")		/* MACHO_CPU_TYPE_ARM64_32 */
					|| (archName == "arm64_32v8")
					|| (archName == "ppc")			/* MACHO_CPU_TYPE_POWERPC */
					|| (archName == "ppc601")
					|| (archName == "ppc602")
					|| (archName == "ppc603")
					|| (archName == "ppc603e")
					|| (archName == "ppc603ev")
					|| (archName == "ppc604")
					|| (archName == "ppc604e")
					|| (archName == "ppc620")
					|| (archName == "ppc750")
					|| (archName == "ppc7400")
					|| (archName == "ppc7450")
					|| (archName == "ppc970")
					|| (archName == "ppc64")		/* MACHO_CPU_TYPE_POWERPC64 */
					)
				{
					m_logger->LogAlert(
						"Binary Ninja free does not support Mach-O architecture '%s'. "
						"Purchase Binary Ninja to unlock all features.",
						archName.c_str());
					return false;
				}
				#endif

				m_logger->LogAlert(
					"Mach-O architecture '%s' is not explicitly supported. Try 'Open with Options' to manually select "
				    "a compatible architecture.",
					archName.c_str());
			}
			else
			{
				m_logger->LogAlert(
					"Mach-O architecture 0x%x is not explicitly supported. Try 'Open with Options' to manually select "
				    "a compatible architecture.",
					m_archId);
			}

			return false;
		}

		// Apply architecture and platform
		Ref<Platform> platform = m_plat ? m_plat : g_machoViewType->GetPlatform(0, m_arch);
		if (!platform)
			platform = m_arch->GetStandalonePlatform();

		if (header.m_entryPoints.size() > 0)
			platform = platform->GetAssociatedPlatformByAddress(header.m_entryPoints[0]);

		SetDefaultPlatform(platform);
		SetDefaultArchitecture(platform->GetArchitecture());

		// Finished for parse only mode
		if (m_parseOnly)
			return true;
	}

	if (m_parseOnly)
		return true;

	BinaryReader reader(GetParentView());
	reader.SetEndianness(m_endian);
	reader.SetVirtualBase(m_universalImageOffset);
	BinaryReader virtualReader(this);
	virtualReader.SetEndianness(m_endian);

	bool parseObjCStructs = true;
	bool parseCFStrings = true;
	if (settings && settings->Contains("loader.macho.processObjectiveC"))
		parseObjCStructs = settings->Get<bool>("loader.macho.processObjectiveC", this);
	if (settings && settings->Contains("loader.macho.processCFStrings"))
		parseCFStrings = settings->Get<bool>("loader.macho.processCFStrings", this);
	if (!ObjCProcessor::ViewHasObjCMetadata(this))
		parseObjCStructs = false;
	if (!GetSectionByName("__cfstring"))
		parseCFStrings = false;
	if (parseObjCStructs || parseCFStrings)
	{
		m_objcProcessor = new ObjCProcessor(this, m_backedByDatabase);
	}
	if (parseObjCStructs)
	{
		if (!settings) // Add our defaults
		{
			Ref<Settings> programSettings = Settings::Instance();
			if (programSettings->Contains("corePlugins.workflows.objc"))
			{
				if (programSettings->Get<bool>("corePlugins.workflows.objc"))
				{
					programSettings->Set("analysis.workflows.functionWorkflow", "core.function.objectiveC", this);
				}
			}
		}
	}

	// parse thread starts section if available
	bool rebaseThreadStarts = false;
	auto theadStartSection = GetSectionByName("__thread_starts");
	vector<uint32_t> threadStarts;
	uint64_t stepMultiplier;
	if (theadStartSection)
	{
		size_t count = theadStartSection->GetLength() / 4;
		threadStarts.reserve(count);
		virtualReader.Seek(theadStartSection->GetStart());
		stepMultiplier = virtualReader.Read32() & 0x1 ? 8 : 4;
		for (uint32_t i = 1; i < count; i++)
			threadStarts.push_back(virtualReader.Read32());

		rebaseThreadStarts = true;
		if (settings && settings->Contains("loader.macho.rebaseThreadStarts"))
			rebaseThreadStarts = settings->Get<bool>("loader.macho.rebaseThreadStarts", this);
	}

	if (rebaseThreadStarts)
		RebaseThreadStarts(virtualReader, threadStarts, stepMultiplier);

	// Add module Init functions if they exist
	size_t modInitFuncCnt = 0;
	for (const auto& moduleInitSection : header.moduleInitSections)
	{
		// ignore mod_init functions that are rebased as part of thread starts
		if (find(threadStarts.begin(), threadStarts.end(), moduleInitSection.offset) != threadStarts.end())
			continue;

		// The mod_init section contains a list of function pointers called at initialization
		// if we don't have a defined entrypoint then use the first one in the list as the entrypoint
		size_t i = 0;
		reader.Seek(moduleInitSection.offset);
		for (; i < (moduleInitSection.size / m_addressSize); i++)
		{
			uint64_t target = (m_addressSize == 4) ? reader.Read32() : reader.Read64();
			target += m_imageBaseAdjustment;
			if (m_header.ident.filetype == MH_FILESET)
			{
				// FIXME: This isn't a super robust way of detagging,
				// 	  should look into xnu source and the tools used to build this cache (if they're public)
				//	  and see if anything better can be done

				// mask out top 8 bits
				uint64_t tag = 0xFFFFFFFF00000000 & header.textBase;
				// and combine them with bottom 8 of the original entry
				target = tag | (target & 0xFFFFFFFF);
			}
			Ref<Platform> targetPlatform = GetDefaultPlatform()->GetAssociatedPlatformByAddress(target);
			auto name = "mod_init_func_" + to_string(modInitFuncCnt++);
			AddEntryPointForAnalysis(targetPlatform, target);
			auto symbol = new Symbol(FunctionSymbol, name, target, GlobalBinding);
			DefineAutoSymbol(symbol);
		}
	}

	if (isMainHeader)
	{
		vector<Ref<Metadata>> libraries;
		vector<Ref<Metadata>> libraryFound;
		for (auto& [libName, libVersion] : header.dylibs)
		{
			if (!GetExternalLibrary(libName))
			{
				AddExternalLibrary(libName, {}, true);
			}
			libraries.push_back(new Metadata(string(libName)));
			// Compose exact name with {install_name}.{platform}.{version}
			std::string libNameExact = fmt::format("{}.{}.{}", libName, GetDefaultPlatform()->GetName(), libVersion);
			Ref<TypeLibrary> typeLib = GetTypeLibrary(libNameExact);
			if (!typeLib)
			{
				vector<Ref<TypeLibrary>> typeLibs = GetDefaultPlatform()->GetTypeLibrariesByName(libNameExact);
				if (typeLibs.size())
				{
					typeLib = typeLibs[0];
					AddTypeLibrary(typeLib);

					m_logger->LogDebug("mach-o: adding type library for '%s': %s (%s)",
						libName.c_str(), typeLib->GetName().c_str(), typeLib->GetGuid().c_str());
				}
			}
			if (!typeLib)
			{
				typeLib = GetTypeLibrary(libName);
				if (!typeLib)
				{
					vector<Ref<TypeLibrary>> typeLibs = GetDefaultPlatform()->GetTypeLibrariesByName(libName);
					if (typeLibs.size())
					{
						typeLib = typeLibs[0];
						AddTypeLibrary(typeLib);

						m_logger->LogDebug("mach-o: adding type library for '%s': %s (%s)",
							libName.c_str(), typeLib->GetName().c_str(), typeLib->GetGuid().c_str());
					}
				}
			}

			if (typeLib)
				libraryFound.push_back(new Metadata(typeLib->GetName()));
			else
				libraryFound.push_back(new Metadata(string("")));
		}
		StoreMetadata("Libraries", new Metadata(libraries), true);
		StoreMetadata("LibraryFound", new Metadata(libraryFound), true);
	}

	bool first = true;
	for (auto entry : header.m_entryPoints)
	{
		if (m_header.ident.filetype == MH_FILESET)
		{
			// FIXME: This isn't a super robust way of detagging,
			// 	  should look into xnu source and the tools used to build this cache (if they're public)
			//	  and see if anything better can be done

			// mask out top 8 bits
			uint64_t tag = 0xFFFFFFFF00000000 & header.textBase;
			// and combine them with bottom 8 of the original entry
			entry = tag | (entry & 0xFFFFFFFF);
		}
		// We set the BinaryView's default platform based on this already modified entry point address
		// 	so we do not need to (again) GetAssociatedPlatformByAddress here.
		AddEntryPointForAnalysis(GetDefaultPlatform(), entry);
		if (first)
		{
			first = false;
			DefineAutoSymbol(new Symbol(FunctionSymbol, "_start", entry));
		}
	}

	vector<uint32_t> indirectSymbols;
	try
	{
		// Handle indirect symbols
		if (header.dysymtab.nindirectsyms)
		{
			indirectSymbols.resize(header.dysymtab.nindirectsyms);
			reader.Seek(header.dysymtab.indirectsymoff);
			reader.Read(&indirectSymbols[0], header.dysymtab.nindirectsyms * sizeof(uint32_t));
		}
	}
	catch (ReadException&)
	{
		m_logger->LogError("Failed to read indirect symbol data");
	}

	bool parseFunctionStarts = true;
	if (settings && settings->Contains("loader.macho.processFunctionStarts"))
		parseFunctionStarts = settings->Get<bool>("loader.macho.processFunctionStarts", this);

	if (parseFunctionStarts)
	{
		m_logger->LogDebug("Parsing function starts\n");
		if (header.functionStartsPresent)
			ParseFunctionStarts(GetDefaultPlatform(), header.textBase, header.functionStarts);
	}

	BeginBulkModifySymbols();
	m_symbolQueue = new SymbolQueue();

	try
	{
		// Add functions for all function symbols
		m_logger->LogDebug("Parsing symbol table\n");
		ParseSymbolTable(reader, header, header.symtab, indirectSymbols);
	}
	catch (std::exception&)
	{
		m_logger->LogError("Failed to parse symbol table!");
	}

	m_symbolQueue->Process();
	delete m_symbolQueue;
	m_symbolQueue = nullptr;

	EndBulkModifySymbols();

	for (auto& relocation : header.rebaseRelocations)
	{
		uint64_t relocationLocation = relocation.address;
		virtualReader.Seek(relocationLocation);
		uint64_t target = virtualReader.ReadPointer();
		uint64_t slidTarget = target + m_imageBaseAdjustment;
		relocation.address = slidTarget;
		DefineRelocation(m_arch, relocation, slidTarget, relocationLocation);
		if (m_objcProcessor)
			m_objcProcessor->AddRelocatedPointer(relocationLocation, slidTarget);
	}
	for (auto& [relocation, name] : header.externalRelocations)
	{
		if (auto symbol = GetSymbolByRawName(name, GetExternalNameSpace()); symbol)
			DefineRelocation(m_arch, relocation, symbol, relocation.address);
	}

	auto relocationHandler = m_arch->GetRelocationHandler("Mach-O");
	if (relocationHandler)
	{
		// FIXME: this if statement block really needs to be a function
		try
		{
			// For executables the relocations are attached to each of the sections
			// In libraries these are zeroed out and collected in the dysymtab
			vector<BNRelocationInfo> infoList;
			for (auto& section : header.sections)
			{
				if (section.nreloc == 0)
					continue;

				char sectionName[17];
				memcpy(sectionName, section.sectname, sizeof(section.sectname));
				sectionName[16] = 0;

				m_logger->LogDebug("Relocations for section %s", sectionName);
				auto sec = GetSectionByName(sectionName);
				if (!sec)
				{
					m_logger->LogError("Can't find section for %s", sectionName);
					continue;
				}
				for (size_t i = 0; i < section.nreloc; i++)
				{
					relocation_info info;
					reader.Seek(section.reloff + (i * sizeof(relocation_info)));
					reader.Read(&info, sizeof(info));
					BNRelocationInfo result;
					memset(&result, 0, sizeof(result));
					if (ParseRelocationEntry(info, sec->GetStart(), result))
							infoList.push_back(result);
				}
			}

			if (relocationHandler->GetRelocationInfo(this, m_arch, infoList))
			{
				unordered_map<string, vector<Ref<Symbol>>> symbolCache;
				for (auto& reloc: infoList)
				{
					if (reloc.symbolIndex >= m_symbols.size())
							continue;

					// retrieve first symbol that is not a symbol relocation
					vector<Ref<Symbol>> symbols;
					auto symName = m_symbols[reloc.symbolIndex];
					if (auto itr = symbolCache.find(symName); itr != symbolCache.end())
					{
						symbols = itr->second;
					}
					else
					{
						symbols = GetSymbolsByName(symName);
						symbolCache[symName] = symbols;
					}

					for (const auto& symbol : symbols)
					{
							if (symbol->GetAddress() == reloc.address)
								continue;
							DefineRelocation(m_arch, reloc, symbol, reloc.address);
							break;
					}
				}
			}
			infoList.clear();

			// Handle local relocations for dynamic libraries
			for (size_t i = 0; i < header.dysymtab.nlocrel; i++)
			{
				relocation_info info;
				reader.Seek(header.dysymtab.locreloff + (i * sizeof(relocation_info)));
				reader.Read(&info, sizeof(info));
				BNRelocationInfo result;
				memset(&result, 0, sizeof(result));
				if (ParseRelocationEntry(info, header.relocationBase, result))
					infoList.push_back(result);
			}

			if (relocationHandler->GetRelocationInfo(this, m_arch, infoList))
			{
				for (auto& reloc: infoList)
				{
					// TODO will matter once rebasing lands
					if (!reloc.external)
							continue;

					if (reloc.symbolIndex >= m_symbols.size())
							continue;

					// retrieve first symbol that is not a symbol relocation
					auto symbols = GetSymbolsByName(m_symbols[reloc.symbolIndex]);
					for (const auto& symbol : symbols)
					{
							if (symbol->GetAddress() == reloc.address)
								continue;
							DefineRelocation(m_arch, reloc, symbol, reloc.address);
							break;
					}
				}
			}
			infoList.clear();

			// Handle external relocations for dynamic libraries
			for (size_t i = 0; i < header.dysymtab.nextrel; i++)
			{
				relocation_info info;
				reader.Seek(header.dysymtab.extreloff + (i * sizeof(relocation_info)));
				reader.Read(&info, sizeof(info));
				BNRelocationInfo result;
				memset(&result, 0, sizeof(result));
				if (ParseRelocationEntry(info, header.relocationBase, result))
					infoList.push_back(result);
			}

			if (relocationHandler->GetRelocationInfo(this, m_arch, infoList))
			{
				for (auto& reloc: infoList)
				{
					// TODO will matter once rebasing lands
					if (!reloc.external)
							continue;

					if (reloc.symbolIndex >= m_symbols.size())
							continue;

					// retrieve first symbol that is not a symbol relocation
					auto symbols = GetSymbolsByName(m_symbols[reloc.symbolIndex]);
					for (const auto& symbol : symbols)
					{
							if (symbol->GetAddress() == reloc.address)
								continue;
							DefineRelocation(m_arch, reloc, symbol, reloc.address);
							break;
					}
				}
			}
			infoList.clear();
		}
		catch (ReadException&)
		{
			m_logger->LogError("Failed to read relocation data");
		}
	}

	vector<std::tuple<uint64_t, string>> machoHeaderStarts;
	if (isMainHeader) {
		machoHeaderStarts.emplace_back(header.textBase, "");
		if (header.textBase != preferredImageBase)
			machoHeaderStarts.emplace_back(preferredImageBase, preferredImageBaseDesc);
	}
	else {
		machoHeaderStarts.emplace_back(preferredImageBase, preferredImageBaseDesc);
	}

	// Apply Mach-O header types
	for (auto [imageBase, imageDesc] : machoHeaderStarts)
	{
		string errorMsg;
		mach_header_64 mappedIdent;
		uint64_t loadCommandOffset;
		loadCommandOffset = g_machoViewType->ParseHeaders(this, imageBase, mappedIdent, nullptr, nullptr, errorMsg);
		if (!loadCommandOffset)
			continue;

		DefineDataVariable(imageBase, Type::NamedType(this, m_typeNames.headerQualName));
		DefineAutoSymbol(new Symbol(DataSymbol, "__macho_header" + imageDesc, imageBase, LocalBinding));

		try
		{
			virtualReader.Seek(imageBase + loadCommandOffset);
			size_t sectionNum = 0;
			for (size_t i = 0; i < mappedIdent.ncmds; i++)
			{
				load_command load;
				uint64_t curOffset = virtualReader.GetOffset();
				load.cmd = virtualReader.Read32();
				load.cmdsize = virtualReader.Read32();
				uint64_t nextOffset = curOffset + load.cmdsize;
				switch (load.cmd)
				{
				case LC_SEGMENT:
				{
					DefineDataVariable(curOffset, Type::NamedType(this, m_typeNames.loadSegmentCommandQualName));
					virtualReader.SeekRelative(5 * 8);
					size_t numSections = virtualReader.Read32();
					virtualReader.SeekRelative(4);
					for (size_t j = 0; j < numSections; j++)
					{
							DefineDataVariable(virtualReader.GetOffset(), Type::NamedType(this, m_typeNames.sectionQualName));
							DefineAutoSymbol(new Symbol(DataSymbol, "__macho_section" + imageDesc + "_[" + to_string(sectionNum++) + "]", virtualReader.GetOffset(), LocalBinding));
							virtualReader.SeekRelative((8 * 8) + 4);
					}
					break;
				}
				case LC_SEGMENT_64:
				{
					DefineDataVariable(curOffset, Type::NamedType(this, m_typeNames.loadSegment64CommandQualName));
					virtualReader.SeekRelative(7 * 8);
					size_t numSections = virtualReader.Read32();
					virtualReader.SeekRelative(4);
					for (size_t j = 0; j < numSections; j++)
					{
							DefineDataVariable(virtualReader.GetOffset(), Type::NamedType(this, m_typeNames.section64QualName));
							DefineAutoSymbol(new Symbol(DataSymbol, "__macho_section_64" + imageDesc + "_[" + to_string(sectionNum++) + "]", virtualReader.GetOffset(), LocalBinding));
							virtualReader.SeekRelative(10 * 8);
					}
					break;
				}
				case LC_SYMTAB:
					DefineDataVariable(curOffset, Type::NamedType(this, m_typeNames.symtabQualName));
					break;
				case LC_DYSYMTAB:
					DefineDataVariable(curOffset, Type::NamedType(this, m_typeNames.dynsymtabQualName));
					break;
				case LC_UUID:
					DefineDataVariable(curOffset, Type::NamedType(this, m_typeNames.uuidQualName));
					break;
				case LC_ID_DYLIB:
				case LC_LOAD_DYLIB:
				case LC_REEXPORT_DYLIB:
				case LC_LOAD_WEAK_DYLIB:
				case LC_LOAD_UPWARD_DYLIB:
					DefineDataVariable(curOffset, Type::NamedType(this, m_typeNames.dylibCommandQualName));
					if (load.cmdsize-24 <= 150)
							DefineDataVariable(curOffset + 24, Type::ArrayType(Type::IntegerType(1, true), load.cmdsize-24));
					break;
				case LC_CODE_SIGNATURE:
				case LC_SEGMENT_SPLIT_INFO:
				case LC_FUNCTION_STARTS:
				case LC_DATA_IN_CODE:
				case LC_DYLIB_CODE_SIGN_DRS:
				case LC_DYLD_EXPORTS_TRIE:
				case LC_DYLD_CHAINED_FIXUPS:
					DefineDataVariable(curOffset, Type::NamedType(this, m_typeNames.linkeditDataQualName));
					break;
				case LC_ENCRYPTION_INFO:
					DefineDataVariable(curOffset, Type::NamedType(this, m_typeNames.encryptionInfoQualName));
					break;
				case LC_VERSION_MIN_MACOSX:
				case LC_VERSION_MIN_IPHONEOS:
					DefineDataVariable(curOffset, Type::NamedType(this, m_typeNames.versionMinQualName));
					break;
				case LC_DYLD_INFO:
				case LC_DYLD_INFO_ONLY:
					DefineDataVariable(curOffset, Type::NamedType(this, m_typeNames.dyldInfoQualName));
					break;
				case LC_FILESET_ENTRY:
					DefineDataVariable(curOffset, Type::NamedType(this, m_typeNames.filesetEntryCommandQualName));
					if (load.cmdsize-0x20 <= 150)
							DefineDataVariable(curOffset + 0x20, Type::ArrayType(Type::IntegerType(1, true), load.cmdsize-0x20));
					break;
				default:
					DefineDataVariable(curOffset, Type::NamedType(this, m_typeNames.loadCommandQualName));
					break;
				}

				DefineAutoSymbol(new Symbol(DataSymbol, "__macho_load_command" + imageDesc + "_[" + to_string(i) + "]", curOffset, LocalBinding));
				virtualReader.Seek(nextOffset);
			}
		}
		catch (ReadException&)
		{
			LogError("Error when applying Mach-O header types at %" PRIx64, imageBase);
		}
	}

	if (parseCFStrings)
	{
		try {
			m_objcProcessor->ProcessCFStrings();
		}
		catch (std::exception& ex)
		{
			m_logger->LogError("Failed to process CFStrings. Binary may be malformed");
			m_logger->LogError("Error: %s", ex.what());
		}
	}

	if (parseObjCStructs)
	{
		try {
			m_objcProcessor->ProcessObjCData();
		}
		catch (std::exception& ex)
		{
			m_logger->LogError("Failed to process Objective-C Metadata. Binary may be malformed");
			m_logger->LogError("Error: %s", ex.what());
		}
		delete m_objcProcessor;
	}


	return true;
}


Ref<Symbol> MachoView::DefineMachoSymbol(
	BNSymbolType type, const string& name, uint64_t addr, BNSymbolBinding binding, bool deferred)
{
	// If name is empty, symbol is not valid
	if (name.size() == 0)
		return nullptr;

	if (type != ExternalSymbol)
	{
		// Don't create symbols that are present in the database snapshot now. If it is not a
		// deferrable symbol, it may be used in relocations, so don't ignore those.
		if (m_backedByDatabase && deferred)
			return nullptr;

		// Ensure symbol is within the executable
		bool ok = false;
		for (auto& segment : m_header.segments)
		{
			if ((segment.initprot == MACHO_VM_PROT_NONE) || (!segment.vmsize))
				continue;

			if ((addr >= segment.vmaddr) &&
				(addr < (segment.vmaddr + segment.vmsize)))
			{
				ok = true;
				break;
			}
		}
		if (!ok)
			return nullptr;
	}

	Ref<Type> symbolTypeRef;

	if ((type == ExternalSymbol) || (type == ImportAddressSymbol) || (type == ImportedDataSymbol))
	{
		QualifiedName n(name);
		Ref<TypeLibrary> appliedLib;
		symbolTypeRef = ImportTypeLibraryObject(appliedLib, n);
		if (symbolTypeRef)
		{
			m_logger->LogDebug("mach-o: type Library '%s' found hit for '%s'", appliedLib->GetName().c_str(), name.c_str());
			RecordImportedObjectLibrary(GetDefaultPlatform(), addr, appliedLib, n);
		}

	}

	auto process = [=]() {
		// If name does not start with alphabetic character or symbol, prepend an underscore
		string rawName = name;
		if (!(((name[0] >= 'A') && (name[0] <= 'Z')) || ((name[0] >= 'a') && (name[0] <= 'z')) || (name[0] == '_')
				|| (name[0] == '?') || (name[0] == '$') || (name[0] == '@')))
			rawName = "_" + name;

		NameSpace nameSpace = GetInternalNameSpace();
		if (type == ExternalSymbol)
		{
			nameSpace = GetExternalNameSpace();
		}

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
			else
			{
				m_logger->LogDebug("Failed to demangle name: '%s'\n", rawName.c_str());
			}
		}

		return std::pair<Ref<Symbol>, Ref<Type>>(
			new Symbol(type, shortName, fullName, rawName, addr, binding, nameSpace), typeRef);
	};

	if (deferred)
	{
		m_symbolQueue->Append(process, [this](Symbol* symbol, Type* type) {
			DefineAutoSymbolAndVariableOrFunction(GetDefaultPlatform(), symbol, type);
		});
		return nullptr;
	}

	auto result = process();
	return DefineAutoSymbolAndVariableOrFunction(GetDefaultPlatform(), result.first, result.second);
}

bool MachoView::GetSegmentPermissions(MachOHeader& header, uint64_t address, uint32_t &flags)
{
	for (auto& segment : header.segments)
	{
		if ((segment.initprot == MACHO_VM_PROT_NONE) || (!segment.vmsize))
			continue;

		if (address >= segment.vmaddr && address < (segment.vmaddr + segment.vmsize))
		{
			flags = segment.flags;
			return true;
		}
	}
	flags = 0;
	return false;
}

bool MachoView::GetSectionPermissions(MachOHeader& header, uint64_t address, uint32_t &flags)
{
	for (auto& section : header.sections)
	{
		if (!section.size)
			continue;

		if (address >= section.addr && address < (section.addr + section.size))
		{
			flags = section.flags;
			return true;
		}
	}
	flags = 0;
	return false;
}

void MachoView::ParseExportTrie(BinaryReader& reader, linkedit_data_command exportTrie)
{
	try {
		uint32_t endGuard = exportTrie.datasize;
		DataBuffer buffer = GetParentView()->ReadBuffer(m_universalImageOffset + exportTrie.dataoff, exportTrie.datasize);

		ReadExportNode(GetStart(), buffer, "", 0, endGuard);
	}
	catch (ReadException&)
	{
		m_logger->LogError("Error while parsing Export Trie");
	}
}

void MachoView::ReadExportNode(uint64_t viewStart, DataBuffer& buffer, const std::string& currentText, size_t cursor, uint32_t endGuard)
{
	if (cursor > endGuard)
		throw ReadException();

	uint64_t terminalSize = readValidULEB128(buffer, cursor);
	uint64_t childOffset = cursor + terminalSize;
	if (terminalSize != 0) {
		uint64_t imageOffset = 0;
		uint64_t flags = readValidULEB128(buffer, cursor);
		if (!(flags & EXPORT_SYMBOL_FLAGS_REEXPORT))
		{
			imageOffset = readValidULEB128(buffer, cursor);
			auto symbolType = GetAnalysisFunctionsForAddress(viewStart + imageOffset).size() ? FunctionSymbol : DataSymbol;
			DefineMachoSymbol(symbolType, currentText, imageOffset + viewStart, GlobalBinding, true);
		}
	}
	cursor = childOffset;
	uint8_t childCount = buffer[cursor];
	cursor++;
	if (cursor > endGuard)
		throw ReadException();
	for (uint8_t i = 0; i < childCount; ++i)
	{
		std::string childText;
		while (buffer[cursor] != 0 & cursor <= endGuard)
			childText.push_back(buffer[cursor++]);
		cursor++;
		if (cursor > endGuard)
			throw ReadException();
		auto next = readValidULEB128(buffer, cursor);
		if (next == 0)
			throw ReadException();
		ReadExportNode(viewStart, buffer, currentText + childText, next, endGuard);
	}
}


void MachoView::ParseRebaseTable(BinaryReader& reader, MachOHeader& header, uint32_t tableOffset, uint32_t tableSize)
{
	if (tableSize == 0 || tableOffset == 0)
		return;

	std::function segmentActualLoadAddress = [&](uint64_t segmentIndex) {
		if (segmentIndex >= header.segments.size())
			throw ReadException();
		return header.segments[segmentIndex].vmaddr;
	};
	std::function segmentActualEndAddress = [&](uint64_t segmentIndex) {
		if (segmentIndex >= header.segments.size())
			throw ReadException();
		return header.segments[segmentIndex].vmaddr + header.segments[segmentIndex].vmsize;
	};

	try {
		reader.Seek(tableOffset);
		auto table = reader.Read(tableSize);

		BNRelocationInfo rebaseRelocation;

		uint64_t segmentIndex = 0;
		uint64_t address = segmentActualLoadAddress(0);
		uint64_t segmentStartAddress = segmentActualLoadAddress(0);
		uint64_t segmentEndAddress = segmentActualEndAddress(0);
		uint64_t count;
		uint64_t skip;
		bool done = false;
		size_t i = 0;
		while ( !done && (i < tableSize))
		{
			uint8_t opAndIm = table[i];
			uint8_t opcode = opAndIm & RebaseOpcodeMask;
			uint64_t immediate = opAndIm & RebaseImmediateMask;
			m_logger->LogDebug("Rebase opcode 0x%llx (im: 0x%llx)", opcode, immediate);
			i++;
			switch (opcode)
			{
			case RebaseOpcodeDone:
				done = true;
				break;
			case RebaseOpcodeSetTypeImmediate:
				break;
			case RebaseOpcodeSetSegmentAndOffsetUleb:
				segmentIndex = immediate;
				address = segmentActualLoadAddress(segmentIndex) + readLEB128(table, tableSize, i);
				segmentStartAddress = segmentActualLoadAddress(segmentIndex);
				segmentEndAddress = segmentActualEndAddress(segmentIndex);
				break;
			case RebaseOpcodeAddAddressUleb:
				address += readLEB128(table, tableSize, i);
				break;
			case RebaseOpcodeAddAddressImmediateScaled:
				address += immediate * m_addressSize;
				break;
			case RebaseOpcodeDoRebaseImmediateTimes:
				count = immediate;
				for (uint64_t j = 0; j < count; ++j)
				{
					m_logger->LogDebug("Rebasing address %llx", address);
					if (address < segmentStartAddress || address >= segmentEndAddress)
					{
						m_logger->LogError("Rebase address out of segment bounds");
						throw ReadException();
					}
					memset(&rebaseRelocation, 0, sizeof(rebaseRelocation));
					rebaseRelocation.nativeType = BINARYNINJA_MANUAL_RELOCATION;
					rebaseRelocation.address = address;
					rebaseRelocation.size = m_addressSize;
					rebaseRelocation.pcRelative = false;
					rebaseRelocation.external = false;
					header.rebaseRelocations.push_back(rebaseRelocation);
					address += m_addressSize;
				}
				break;
			case RebaseOpcodeDoRebaseUlebTimes:
				count = readLEB128(table, tableSize, i);
				for (uint64_t j = 0; j < count; ++j)
				{
					m_logger->LogDebug("Rebasing address %llx", address);
					if (address < segmentStartAddress || address >= segmentEndAddress)
					{
						m_logger->LogError("Rebase address out of segment bounds");
						throw ReadException();
					}
					memset(&rebaseRelocation, 0, sizeof(rebaseRelocation));
					rebaseRelocation.nativeType = BINARYNINJA_MANUAL_RELOCATION;
					rebaseRelocation.address = address;
					rebaseRelocation.size = m_addressSize;
					rebaseRelocation.pcRelative = false;
					rebaseRelocation.external = false;
					header.rebaseRelocations.push_back(rebaseRelocation);
					address += m_addressSize;
				}
				break;
			case RebaseOpcodeDoRebaseAddAddressUleb:
				m_logger->LogDebug("Rebasing address %llx", address);
				if (address < segmentStartAddress || address >= segmentEndAddress)
				{
					m_logger->LogError("Rebase address out of segment bounds");
					throw ReadException();
				}
				memset(&rebaseRelocation, 0, sizeof(rebaseRelocation));
				rebaseRelocation.nativeType = BINARYNINJA_MANUAL_RELOCATION;
				rebaseRelocation.address = address;
				rebaseRelocation.size = m_addressSize;
				rebaseRelocation.pcRelative = false;
				rebaseRelocation.external = false;
				header.rebaseRelocations.push_back(rebaseRelocation);
				address += readLEB128(table, tableSize, i) + m_addressSize;
				break;
			case RebaseOpcodeDoRebaseUlebTimesSkippingUleb:
				count = readLEB128(table, tableSize, i);
				skip = readLEB128(table, tableSize, i);
				for (uint64_t j = 0; j < count; ++j)
				{
					m_logger->LogDebug("Rebasing address %llx", address);
					if (address < segmentStartAddress || address >= segmentEndAddress)
					{
						m_logger->LogError("Rebase address out of segment bounds");
						throw ReadException();
					}
					memset(&rebaseRelocation, 0, sizeof(rebaseRelocation));
					rebaseRelocation.nativeType = BINARYNINJA_MANUAL_RELOCATION;
					rebaseRelocation.address = address;
					rebaseRelocation.size = m_addressSize;
					rebaseRelocation.pcRelative = false;
					rebaseRelocation.external = false;
					header.rebaseRelocations.push_back(rebaseRelocation);
					address += skip + m_addressSize;
				}
				break;
			default:
				m_logger->LogError("Unknown rebase opcode %d", opcode);
				throw ReadException();
				break;
			}
		}
	}
	catch (ReadException&)
	{
		m_logger->LogError("Error while parsing Rebase Table");
	}
}


void MachoView::ParseDynamicTable(BinaryReader& reader, MachOHeader& header, BNSymbolType incomingType, uint32_t tableOffset,
	uint32_t tableSize, BNSymbolBinding binding)
{
	try {
		reader.Seek(tableOffset);
		auto table = reader.Read(tableSize);
		BNRelocationInfo externReloc;

		BNSymbolType symtype = incomingType;
		// uint64_t ordinal = 0;
		// int64_t addend = 0;
		uint64_t segmentIndex = 0;
		uint64_t address = 0;
		uint64_t offset = 0;
		char* name = NULL;
		// uint32_t flags = 0;
		uint32_t type = 0;
		size_t i = 0;
		//bool done = false;
		while (i < tableSize)
		{
			uint8_t opcode = table[i] & BindOpcodeMask;
			uint8_t imm = table[i] & BindImmediateMask;
			i++;
			switch (opcode)
			{
				case BindOpcodeDone:
					// ordinal = 0;
					// addend  = 0;
					segmentIndex = 0;
					address = 0;
					offset = 0;
					name = NULL;
					// flags = 0;
					type = 0;
					symtype = incomingType;
					break;
				case BindOpcodeSetDylibOrdinalImmediate: /* ordinal = imm; */ break;
				case BindOpcodeSetDylibOrdinalULEB: /* ordinal = */ readLEB128(table, tableSize, i); break;
				case BindOpcodeSetDylibSpecialImmediate: /* ordinal = -imm; */ break;
				case BindOpcodeSetSymbolTrailingFlagsImmediate:
					/* flags = imm; */
					name = (char*)&table[i];
					while (i < tableSize && table[i++] != '\0')
					{;}
					break;
				case BindOpcodeSetTypeImmediate:
					type = imm;
					if (type == 1)
						symtype = ImportedDataSymbol;
					break;
				case BindOpcodeSetAddendSLEB: /* addend = */ readSLEB128(table, tableSize, i); break;
				case BindOpcodeSetSegmentAndOffsetULEB:
					segmentIndex = imm;
					offset = readLEB128(table, tableSize, i);
					if (segmentIndex >= header.segments.size())
						throw MachoFormatException();
					address = header.segments[segmentIndex].vmaddr + offset;
					break;
				case BindOpcodeAddAddressULEB:
					address += readLEB128(table, tableSize, i);
					break;
				case BindOpcodeDoBind:
					if (name == NULL)
						throw MachoFormatException();

					DefineMachoSymbol(symtype, string(name), address, binding, true);

					memset(&externReloc, 0, sizeof(externReloc));
					externReloc.nativeType = BINARYNINJA_MANUAL_RELOCATION;
					externReloc.address = address;
					externReloc.size = m_addressSize;
					externReloc.pcRelative = false;
					externReloc.external = true;
					header.externalRelocations.emplace_back(externReloc, string(name));

					address += m_addressSize;
					break;
				case BindOpcodeDoBindAddAddressULEB:
					if (name == NULL)
						throw MachoFormatException();

					DefineMachoSymbol(symtype, string(name), address, binding, true);

					memset(&externReloc, 0, sizeof(externReloc));
					externReloc.nativeType = BINARYNINJA_MANUAL_RELOCATION;
					externReloc.address = address;
					externReloc.size = m_addressSize;
					externReloc.pcRelative = false;
					externReloc.external = true;
					header.externalRelocations.emplace_back(externReloc, string(name));

					address += m_addressSize;
					address += readLEB128(table, tableSize, i);
					break;
				case BindOpcodeDoBindAddAddressImmediateScaled:
					if (name == NULL)
						throw MachoFormatException();

					DefineMachoSymbol(symtype, string(name), address, binding, true);

					memset(&externReloc, 0, sizeof(externReloc));
					externReloc.nativeType = BINARYNINJA_MANUAL_RELOCATION;
					externReloc.address = address;
					externReloc.size = m_addressSize;
					externReloc.pcRelative = false;
					externReloc.external = true;
					header.externalRelocations.emplace_back(externReloc, string(name));
					address += m_addressSize;
					address += (imm * m_addressSize);
					break;
				case BindOpcodeDoBindULEBTimesSkippingULEB:
				{
					if (name == NULL)
						throw MachoFormatException();

					uint64_t count = readLEB128(table, tableSize, i);
					uint64_t skip = readLEB128(table, tableSize, i);
					for (; count > 0; count--)
					{
						DefineMachoSymbol(symtype, string(name), address, binding, true);

						memset(&externReloc, 0, sizeof(externReloc));
						externReloc.nativeType = BINARYNINJA_MANUAL_RELOCATION;
						externReloc.address = address;
						externReloc.size = m_addressSize;
						externReloc.pcRelative = false;
						externReloc.external = true;
						header.externalRelocations.emplace_back(externReloc, string(name));

						address += skip + m_addressSize;
					}
					break;
				}
				// New Threaded Binding Opcode, not much info out about it. It encodes a ULEB after the op/imm.
				case 0xD0: readLEB128(table, tableSize, i); break;
				default:
					break;
			}
		}
	}
	catch (ReadException&)
	{;}
}


void MachoView::ParseSymbolTable(BinaryReader& reader, MachOHeader& header, const symtab_command& symtab, const vector<uint32_t>& indirectSymbols)
{
	if (header.ident.filetype == MH_DSYM)
	{
		m_logger->LogDebug("Skipping symbol parsing");
		return;
	}

	try
	{
		//First parse the imports
		if (header.dyldInfoPresent)
		{
			m_logger->LogDebug("Bind symbols");
			ParseDynamicTable(reader, header, ImportAddressSymbol, header.dyldInfo.bind_off,
					  header.dyldInfo.bind_size, GlobalBinding);
			m_logger->LogDebug("Weak symbols");
			ParseDynamicTable(reader, header, ImportAddressSymbol, header.dyldInfo.weak_bind_off,
					  header.dyldInfo.weak_bind_size, WeakBinding);
			m_logger->LogDebug("Lazy symbols");
			ParseDynamicTable(reader, header, ImportAddressSymbol, header.dyldInfo.lazy_bind_off,
					  header.dyldInfo.lazy_bind_size, GlobalBinding);
			m_logger->LogDebug("Parsing rebase table");
			ParseRebaseTable(reader, header, header.dyldInfo.rebase_off, header.dyldInfo.rebase_size);
		}
		if (header.chainedFixupsPresent)
		{
			m_logger->LogDebug("Chained Fixups");
			ParseChainedFixups(header, header.chainedFixups);
		}
		else if (header.chainStartsPresent)
		{
			m_logger->LogDebug("Chained Starts");
			ParseChainedStarts(header, header.chainStarts);
		}
		if (header.exportTriePresent && header.isMainHeader)
			ParseExportTrie(reader, header.exportTrie);

		//Then process the symtab
		if (header.stringListSize == 0)
			return;
		reader.Seek(symtab.symoff);

		unordered_map<size_t, vector<std::pair<section_64*, size_t>>> stubSymbols;
		for (auto& symbolStubs : header.symbolStubSections)
		{
			if (!symbolStubs.reserved2)
				continue;

			size_t needed = symbolStubs.size / symbolStubs.reserved2;
			for (size_t j = 0; (j < needed) && ((j + symbolStubs.reserved1) < indirectSymbols.size()); j++)
			{
				auto symNum = indirectSymbols[j + symbolStubs.reserved1];
				if (symNum == INDIRECT_SYMBOL_ABS)
					continue;
				else if (symNum == INDIRECT_SYMBOL_LOCAL)
					continue;

				stubSymbols[symNum].push_back(
					std::pair<section_64*, size_t>(&symbolStubs, j));
			}
		}

		unordered_map<size_t, vector<std::pair<section_64*, size_t>>> pointerSymbols;
		for (auto& symbolPointerSection : header.symbolPointerSections)
		{
			size_t needed = symbolPointerSection.size / m_addressSize;
			for (size_t j = 0; (j < needed) && ((j + symbolPointerSection.reserved1) < indirectSymbols.size()); j++)
			{
				auto symNum = indirectSymbols[j + symbolPointerSection.reserved1];
				if (symNum == INDIRECT_SYMBOL_ABS)
					continue;
				else if (symNum == INDIRECT_SYMBOL_LOCAL)
					continue;
				pointerSymbols[symNum].push_back(
					std::pair<section_64*, size_t>(&symbolPointerSection, j));
			}
		}

		nlist_64 sym;
		memset(&sym, 0, sizeof(sym));
		for (size_t i = 0; i < symtab.nsyms; i++)
		{
			sym.n_strx = reader.Read32();
			sym.n_type = reader.Read8();
			sym.n_sect = reader.Read8();
			sym.n_desc = reader.Read16();
			sym.n_value = (m_addressSize == 4) ? reader.Read32() : reader.Read64();
			if (sym.n_value)
				sym.n_value += m_imageBaseAdjustment;
			if (sym.n_strx >= symtab.strsize || ((sym.n_type & N_TYPE) == N_INDR))
				continue;

			string symbol((char*)header.stringList->GetDataAt(sym.n_strx));
			m_symbols.push_back(symbol);
			//otool ignores symbols that end with ".o", startwith "ltmp" or are "gcc_compiled." so do we
			if (symbol == "gcc_compiled." ||
				(symbol.length() > 2 && symbol.substr(symbol.length()-2, 2) == ".o") ||
				(symbol.length() > 4 && symbol.substr(0, 4) == "ltmp"))
			{
				m_logger->LogDebug("Skipping symbol: %s.", symbol.c_str());
				continue;
			}
			//N_TYPE is only set when N_SECT is the integer count of the section the symbol is in
			//Note that we don't currently validate the section number, but just use the address.
			//Very curious to see how other tools handle it.
			BNSymbolType type = DataSymbol;
			uint32_t flags;
			if ((sym.n_type & N_TYPE) == N_SECT && sym.n_sect > 0 && (size_t)(sym.n_sect - 1) < header.sections.size())
			{
				if (!GetSectionPermissions(header, sym.n_value, flags))
				{
					if ((sym.n_type & N_EXT))
					{
						if (!GetSegmentPermissions(header, sym.n_value, flags))
						{
							m_logger->LogDebug("No valid segment for symbol %s. value:%" PRIx64, symbol.c_str(), sym.n_value);
							continue;
						}
					}
					else
					{
						m_logger->LogDebug("No valid section for symbol %s. value:%" PRIx64, symbol.c_str(), sym.n_value);
						continue;
					}
				}
			}
			else if ((sym.n_type & N_TYPE) == N_ABS)
			{
				//N_ABS symbols do not have a section. Fall back to segment permissions.
				if (!GetSegmentPermissions(header, sym.n_value, flags))
				{
					m_logger->LogDebug("No valid segment for symbol %s. value:%" PRIx64, symbol.c_str(), sym.n_value);
					continue;
				}
			}
			else if ((sym.n_type & N_EXT))
			{
				type = ExternalSymbol;
			}
			else
				continue;

			if (type != ExternalSymbol)
			{
				if ((flags & S_ATTR_PURE_INSTRUCTIONS) == S_ATTR_PURE_INSTRUCTIONS ||
					(flags & S_ATTR_SOME_INSTRUCTIONS) == S_ATTR_SOME_INSTRUCTIONS)
					type = FunctionSymbol;
				else
					type = DataSymbol;
			}
			if((sym.n_desc & N_ARM_THUMB_DEF) == N_ARM_THUMB_DEF)
				sym.n_value++;

			auto stubSymbolIter = stubSymbols.find(i);
			auto pointerSymbolIter = pointerSymbols.find(i);
			bool deferred = stubSymbolIter == stubSymbols.end() && pointerSymbolIter == pointerSymbols.end();

			Ref<Symbol> symbolObj;
			if(header.dysymtab.nlocalsym && i >= header.dysymtab.ilocalsym && i < header.dysymtab.ilocalsym + header.dysymtab.nlocalsym)
			{
				symbolObj = DefineMachoSymbol(type, symbol, sym.n_value, LocalBinding, deferred);
			}
			else if (header.dysymtab.nextdefsym && i >= header.dysymtab.iextdefsym && i < header.dysymtab.iextdefsym + header.dysymtab.nextdefsym)
			{
				symbolObj = DefineMachoSymbol(type, symbol, sym.n_value, GlobalBinding, deferred);
			}
			else if (header.dysymtab.nundefsym && i >= header.dysymtab.iundefsym && i < header.dysymtab.iundefsym + header.dysymtab.nundefsym)
			{
				symbolObj = DefineMachoSymbol(type, symbol, sym.n_value, GlobalBinding, deferred);
			}
			else
			{
				symbolObj = DefineMachoSymbol(type, symbol, sym.n_value, GlobalBinding, deferred);
			}

			if (!symbolObj)
			{
				continue;
			}

			if (stubSymbolIter != stubSymbols.end())
			{
				for (auto& j : stubSymbolIter->second)
				{
					// m_logger->LogError("STUB [%d] %llx - %s", i, j.first->addr + (j * j.first->reserved2), symbol.c_str());
					BNRelocationInfo info;
					memset(&info, 0, sizeof(info));
					info.nativeType = -1;
					info.size = j.first->reserved2;
					info.pcRelative = true;
					DefineRelocation(m_arch, info, symbolObj, j.first->addr + (j.second * j.first->reserved2));
					DefineMachoSymbol(ImportedFunctionSymbol, symbol, j.first->addr + (j.second * j.first->reserved2),
						GlobalBinding, true);
				}
			}

			if (pointerSymbolIter != pointerSymbols.end())
			{
				for (auto& j : pointerSymbolIter->second)
				{
					// m_logger->LogError("POINTER [%d] %llx - %s", i, j.first->addr + (j.second * m_addressSize),
					// symbol.c_str());
					BNRelocationInfo info;
					memset(&info, 0, sizeof(info));
					info.nativeType = BINARYNINJA_MANUAL_RELOCATION;
					info.size = m_addressSize;
					info.pcRelative = false;
					DefineRelocation(m_arch, info, symbolObj, j.first->addr + (j.second * m_addressSize));
					DefineMachoSymbol(
						ImportAddressSymbol, symbol, j.first->addr + (j.second * m_addressSize), GlobalBinding, true);
				}
			}
		}
	}
	catch (ReadException&)
	{;}
	return;
}


void MachoView::ParseChainedFixups(MachOHeader& header, linkedit_data_command chainedFixups)
{
	if (!chainedFixups.dataoff)
		return;

	m_logger->LogDebug("Processing Chained Fixups");

	// Dummy relocation
	BNRelocationInfo reloc;
	memset(&reloc, 0, sizeof(BNRelocationInfo));
	reloc.type = StandardRelocationType;
	reloc.size = m_addressSize;
	reloc.nativeType = BINARYNINJA_MANUAL_RELOCATION;

	bool processBinds = true;

	BinaryReader parentReader(GetParentView());
	BinaryReader mappedReader(this);

	try {
		dyld_chained_fixups_header fixupsHeader {};
		uint64_t fixupHeaderAddress = m_universalImageOffset + chainedFixups.dataoff;
		parentReader.Seek(fixupHeaderAddress);
		fixupsHeader.fixups_version = parentReader.Read32();
		fixupsHeader.starts_offset = parentReader.Read32();
		fixupsHeader.imports_offset = parentReader.Read32();
		fixupsHeader.symbols_offset = parentReader.Read32();
		fixupsHeader.imports_count = parentReader.Read32();
		fixupsHeader.imports_format = parentReader.Read32();
		fixupsHeader.symbols_format = parentReader.Read32();

		m_logger->LogDebug("Chained Fixups: Header @ %llx // Fixups version %lx", fixupHeaderAddress, fixupsHeader.fixups_version);

		size_t importsAddress = fixupHeaderAddress + fixupsHeader.imports_offset;
		size_t importTableSize = sizeof(dyld_chained_import) * fixupsHeader.imports_count;

		if (fixupsHeader.fixups_version > 0)
		{
			m_logger->LogError("Chained Fixup parsing failed. Unknown Fixups Version");
			return;
		}

		if (importTableSize > chainedFixups.datasize)
		{
			m_logger->LogError("Chained Fixup parsing failed. Binary is malformed");
			return;
		}

		size_t symbolsAddress = fixupHeaderAddress + fixupsHeader.symbols_offset;

		// Pre-load the import table. We may re-access the same ordinal multiple times, this will be faster.
		std::vector<import_entry> importTable;
		parentReader.Seek(importsAddress);

		switch (fixupsHeader.imports_format)
		{
			case DYLD_CHAINED_IMPORT:
			{
				for (size_t i = 0; i < fixupsHeader.imports_count; i++)
				{
					uint32_t importEntry = parentReader.Read32();
					uint64_t nextEntryAddress = parentReader.GetOffset();

					dyld_chained_import import = *(reinterpret_cast<dyld_chained_import*>(&importEntry));

					import_entry entry;

					entry.lib_ordinal = (uint64_t)import.lib_ordinal;
					entry.addend = 0;
					entry.weak = (import.weak_import == 1);

					size_t symNameAddr = symbolsAddress + import.name_offset;

					parentReader.Seek(symNameAddr);
					try {
						string symbolName = parentReader.ReadCString();
						entry.name = symbolName;
					}
					catch (ReadException& ex)
					{
						entry.name = "";
					}

					importTable.push_back(entry);
					parentReader.Seek(nextEntryAddress);
				}
				break;
			}
			case DYLD_CHAINED_IMPORT_ADDEND:
			case DYLD_CHAINED_IMPORT_ADDEND64:
			default:
			{
				m_logger->LogWarn("Chained Fixups: Unknown import binding format");
				processBinds = false; // We can still handle rebases.
				break;
			}
		}

		m_logger->LogDebug("Chained Fixups: %llx import table entries", importTable.size());

		uint64_t fixupStartsAddress = fixupHeaderAddress + fixupsHeader.starts_offset;
		parentReader.Seek(fixupStartsAddress);
		dyld_chained_starts_in_image segs {};
		segs.seg_count = parentReader.Read32();
		vector<uint32_t> segInfoOffsets {};
		for (size_t i = 0; i < segs.seg_count; i++)
		{
			segInfoOffsets.push_back(parentReader.Read32());
		}
		for (auto offset : segInfoOffsets)
		{
			if (!offset)
				continue;

			dyld_chained_starts_in_segment starts {};
			uint64_t startsAddr = fixupStartsAddress + offset;
			parentReader.Seek(startsAddr);
			starts.size = parentReader.Read32();
			starts.page_size = parentReader.Read16();
			starts.pointer_format = parentReader.Read16();
			starts.segment_offset = parentReader.Read64();
			starts.max_valid_pointer = parentReader.Read32();
			starts.page_count = parentReader.Read16();

			uint8_t strideSize;
			ChainedFixupPointerGeneric format;

			// Firmware formats will require digging up whatever place they're being used and reversing it.
			// They are not handled by dyld.
			switch (starts.pointer_format) {
			case DYLD_CHAINED_PTR_ARM64E:
			case DYLD_CHAINED_PTR_ARM64E_USERLAND:
			case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
				strideSize = 8;
				format = GenericArm64eFixupFormat;
				break;
			case DYLD_CHAINED_PTR_ARM64E_KERNEL:
				strideSize = 4;
				format = GenericArm64eFixupFormat;
				break;
			// case DYLD_CHAINED_PTR_ARM64E_FIRMWARE: Unsupported.
			case DYLD_CHAINED_PTR_64:
			case DYLD_CHAINED_PTR_64_OFFSET:
			case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
				strideSize = 4;
				format = Generic64FixupFormat;
				break;
			case DYLD_CHAINED_PTR_32:
			case DYLD_CHAINED_PTR_32_CACHE:
				strideSize = 4;
				format = Generic32FixupFormat;
				break;
			case DYLD_CHAINED_PTR_32_FIRMWARE:
				strideSize = 4;
				format = Firmware32FixupFormat;
				break;
			case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
				strideSize = 1;
				format = Generic64FixupFormat;
				break;
			default:
			{
				m_logger->LogError("Chained Fixups: Unknown or unsupported pointer format %d, "
					"unable to process chains for segment at @llx", starts.pointer_format, starts.segment_offset);
				continue;
			}
			}

			uint16_t fmt = starts.pointer_format;
			m_logger->LogDebug("Chained Fixups: Segment start @ %llx, fmt %d", starts.segment_offset, fmt);

			uint64_t pageStartsTableStartAddress = parentReader.GetOffset();
			vector<vector<uint16_t>> pageStartOffsets {};
			for (size_t i = 0; i < starts.page_count; i++)
			{
				// On armv7, Chained pointers here can have multiple starts.
				// And if so, there's another table *overlapping* the table we're currently reading.
				// dyld handles this through 'overflow indexing'
				// This is technically supported on other archs however is not (currently) used.
				parentReader.Seek(pageStartsTableStartAddress + (sizeof(uint16_t) * i));
				uint16_t start = parentReader.Read16();
				if ((start & DYLD_CHAINED_PTR_START_MULTI) && (start != DYLD_CHAINED_PTR_START_NONE))
				{
					uint64_t overflowIndex = start & ~DYLD_CHAINED_PTR_START_MULTI;
					vector<uint16_t> pageStartSubStarts;
					parentReader.Seek(pageStartsTableStartAddress + (overflowIndex * sizeof(uint16_t)));
					bool done = false;
					while (!done)
					{
						uint16_t subPageStart = parentReader.Read16();
						if ((subPageStart & DYLD_CHAINED_PTR_START_LAST) == 0)
						{
							pageStartSubStarts.push_back(subPageStart);
						}
						else
						{
							pageStartSubStarts.push_back(subPageStart & ~DYLD_CHAINED_PTR_START_LAST);
							done = true;
						}
					}
					pageStartOffsets.push_back(pageStartSubStarts);
				}
				else
				{
					pageStartOffsets.push_back({start});
				}
			}

			int i = -1;
			for (auto pageStarts : pageStartOffsets)
			{
				i++;
				uint64_t pageAddress = m_universalImageOffset + starts.segment_offset + (i * starts.page_size);
				for (uint16_t start : pageStarts)
				{
					if (start == DYLD_CHAINED_PTR_START_NONE)
						continue;

					uint64_t chainEntryAddress = pageAddress + start;

					bool fixupsDone = false;

					while (!fixupsDone)
					{
						ChainedFixupPointer pointer;
						parentReader.Seek(chainEntryAddress);
						mappedReader.Seek(chainEntryAddress - m_universalImageOffset + GetStart());
						if (format == Generic32FixupFormat || format == Firmware32FixupFormat)
							pointer.raw32 = (uint32_t)(uintptr_t)mappedReader.Read32();
						else
							pointer.raw64 = (uintptr_t)mappedReader.Read64();

						bool bind = false;
						uint64_t nextEntryStrideCount;

						switch (format)
						{
						case Generic32FixupFormat:
							bind = pointer.generic32.bind.bind;
							nextEntryStrideCount = pointer.generic32.rebase.next;
							break;
						case Generic64FixupFormat:
							bind = pointer.generic64.bind.bind;
							nextEntryStrideCount = pointer.generic64.rebase.next;
							break;
						case GenericArm64eFixupFormat:
							bind = pointer.arm64e.bind.bind;
							nextEntryStrideCount = pointer.arm64e.rebase.next;
							break;
						case Firmware32FixupFormat:
							nextEntryStrideCount = pointer.firmware32.next;
							bind = false;
							break;
						}

						m_logger->LogTrace("Chained Fixups: @ 0x%llx ( 0x%llx ) - %d 0x%llx", chainEntryAddress,
							GetStart() + (chainEntryAddress - m_universalImageOffset),
							bind, nextEntryStrideCount);

						if (bind && processBinds)
						{
							uint64_t ordinal;

							switch (starts.pointer_format)
							{
							case DYLD_CHAINED_PTR_64:
							case DYLD_CHAINED_PTR_64_OFFSET:
								ordinal = pointer.generic64.bind.ordinal;
								break;
							// case DYLD_CHAINED_PTR_ARM64E_OFFSET: ; old _KERNEL name.
							case DYLD_CHAINED_PTR_ARM64E:
							case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
							case DYLD_CHAINED_PTR_ARM64E_KERNEL:
								if (pointer.arm64e.bind.auth)
									ordinal = starts.pointer_format == DYLD_CHAINED_PTR_ARM64E_USERLAND24
										? pointer.arm64e.authBind24.ordinal : pointer.arm64e.authBind.ordinal;
								else
									ordinal = starts.pointer_format == DYLD_CHAINED_PTR_ARM64E_USERLAND24
										? pointer.arm64e.bind24.ordinal : pointer.arm64e.bind.ordinal;
								break;
							case DYLD_CHAINED_PTR_32:
								ordinal = pointer.generic32.bind.ordinal;
								break;
							default:
								m_logger->LogWarn("Chained Fixups: Unknown Bind Pointer Format at %llx",
									GetStart() + (chainEntryAddress - m_universalImageOffset));

								chainEntryAddress += (nextEntryStrideCount * strideSize);
								if (chainEntryAddress > pageAddress + starts.page_size)
								{
									m_logger->LogDebug("Chained Fixups: Pointer at %llx left page",
										GetStart() + ((chainEntryAddress - (nextEntryStrideCount * strideSize))) - m_universalImageOffset);
									fixupsDone = true;
								}
								if (nextEntryStrideCount == 0)
									fixupsDone = true;

								continue;
							}

							if (ordinal < importTable.size())
							{
								import_entry entry = importTable.at(ordinal);
								uint64_t targetAddress = GetStart() + (chainEntryAddress - m_universalImageOffset);

								if (!entry.name.empty())
								{
									reloc.address = targetAddress;
									DefineMachoSymbol(ImportAddressSymbol, entry.name,
										targetAddress,
										entry.weak ? WeakBinding : GlobalBinding, true);

									BNRelocationInfo externReloc;
									memset(&externReloc, 0, sizeof(externReloc));
									externReloc.nativeType = BINARYNINJA_MANUAL_RELOCATION;
									externReloc.address = targetAddress;
									externReloc.size = m_addressSize;
									externReloc.pcRelative = false;
									externReloc.external = true;
									header.externalRelocations.emplace_back(externReloc, entry.name);
								}
								else
								{
									m_logger->LogWarn("Chained Fixups: Import Table entry %llx has no symbol; "
										"Unable to bind item at %llx", ordinal, targetAddress);
								}
							}
						}
						else if (!bind)
						{
							uint64_t entryOffset;
							switch (starts.pointer_format)
							{
							case DYLD_CHAINED_PTR_ARM64E:
							case DYLD_CHAINED_PTR_ARM64E_KERNEL:
							case DYLD_CHAINED_PTR_ARM64E_USERLAND:
							case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
							{
								if (pointer.arm64e.bind.auth)
									entryOffset = pointer.arm64e.authRebase.target;
								else
									entryOffset = pointer.arm64e.rebase.target;

								if ( starts.pointer_format != DYLD_CHAINED_PTR_ARM64E || pointer.arm64e.bind.auth)
									entryOffset += GetStart();

								break;
							}
							case DYLD_CHAINED_PTR_64:
								entryOffset = pointer.generic64.rebase.target;
								break;
							case DYLD_CHAINED_PTR_64_OFFSET:
								entryOffset = pointer.generic64.rebase.target + GetStart();
								break;
							case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
							case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
								entryOffset = pointer.kernel64.target;
								break;
							case DYLD_CHAINED_PTR_32:
							case DYLD_CHAINED_PTR_32_CACHE:
								entryOffset = pointer.generic32.rebase.target;
								break;
							case DYLD_CHAINED_PTR_32_FIRMWARE:
								entryOffset = pointer.firmware32.target;
								break;
							}

							reloc.address = GetStart() + (chainEntryAddress - m_universalImageOffset);
							DefineRelocation(m_arch, reloc, entryOffset, reloc.address);

							if (m_objcProcessor)
							{
								m_objcProcessor->AddRelocatedPointer(reloc.address, entryOffset);
							}
						}

						chainEntryAddress += (nextEntryStrideCount * strideSize);

						if (chainEntryAddress > pageAddress + starts.page_size)
						{
							// Something is seriously wrong here. likely malformed binary, or our parsing failed elsewhere.
							// This will log the pointer in mapped memory.
							m_logger->LogError("Chained Fixups: Pointer at %llx left page",
								GetStart() + ((chainEntryAddress - (nextEntryStrideCount * strideSize))) - m_universalImageOffset);
							fixupsDone = true;
						}

						if (nextEntryStrideCount == 0)
							fixupsDone = true;
					}
				}
			}
		}
	}
	catch (ReadException&)
	{
		m_logger->LogError("Chained Fixup parsing failed");
	}
}


void MachoView::ParseChainedStarts(MachOHeader& header, section_64 chainedStarts)
{
	if (!chainedStarts.offset)
		return;

	m_logger->LogDebug("Processing Chained Starts");

	// Dummy relocation
	BNRelocationInfo reloc;
	memset(&reloc, 0, sizeof(BNRelocationInfo));
	reloc.type = StandardRelocationType;
	reloc.size = m_addressSize;
	reloc.nativeType = BINARYNINJA_MANUAL_RELOCATION;

	bool processBinds = true;

	BinaryReader parentReader(GetParentView());
	BinaryReader mappedReader(this);

	try {
		uint64_t fixupHeaderAddress = m_universalImageOffset + chainedStarts.offset;
		parentReader.Seek(fixupHeaderAddress);

		uint32_t pointerFormat = parentReader.Read32();
		uint32_t startsCount = parentReader.Read32();
		std::vector<uint32_t> startsOffsets;
		for (size_t i = 0; i < startsCount; i++)
		{
			startsOffsets.push_back(parentReader.Read32());
		}

		uint8_t strideSize;
		ChainedFixupPointerGeneric format;

		// Firmware formats will require digging up whatever place they're being used and reversing it.
		// They are not handled by dyld.
		switch (pointerFormat) {
		case DYLD_CHAINED_PTR_ARM64E:
		case DYLD_CHAINED_PTR_ARM64E_USERLAND:
		case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
			strideSize = 8;
			format = GenericArm64eFixupFormat;
			break;
		case DYLD_CHAINED_PTR_ARM64E_KERNEL:
			strideSize = 4;
			format = GenericArm64eFixupFormat;
			break;
		// case DYLD_CHAINED_PTR_ARM64E_FIRMWARE: Unsupported.
		case DYLD_CHAINED_PTR_64:
		case DYLD_CHAINED_PTR_64_OFFSET:
		case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
			strideSize = 4;
			format = Generic64FixupFormat;
			break;
		case DYLD_CHAINED_PTR_32:
		case DYLD_CHAINED_PTR_32_CACHE:
			strideSize = 4;
			format = Generic32FixupFormat;
			break;
		case DYLD_CHAINED_PTR_32_FIRMWARE:
			strideSize = 4;
			format = Firmware32FixupFormat;
			break;
		case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
			strideSize = 1;
			format = Generic64FixupFormat;
			break;
		default:
		{
			m_logger->LogError("Chained Starts: Unknown or unsupported pointer format %d, "
				"unable to process chain starts", pointerFormat);
			return;
		}
		}

		for (uint32_t offset : startsOffsets)
		{
			uint64_t chainEntryAddress = m_universalImageOffset + offset;

			bool fixupsDone = false;

			while (!fixupsDone)
			{
				ChainedFixupPointer pointer;
				parentReader.Seek(chainEntryAddress);
				mappedReader.Seek(chainEntryAddress - m_universalImageOffset + GetStart());
				if (format == Generic32FixupFormat || format == Firmware32FixupFormat)
					pointer.raw32 = (uint32_t)(uintptr_t)mappedReader.Read32();
				else
					pointer.raw64 = (uintptr_t)mappedReader.Read64();

				bool bind = false;
				uint64_t nextEntryStrideCount;

				switch (format)
				{
				case Generic32FixupFormat:
					bind = pointer.generic32.bind.bind;
					nextEntryStrideCount = pointer.generic32.rebase.next;
					break;
				case Generic64FixupFormat:
					bind = pointer.generic64.bind.bind;
					nextEntryStrideCount = pointer.generic64.rebase.next;
					break;
				case GenericArm64eFixupFormat:
					bind = pointer.arm64e.bind.bind;
					nextEntryStrideCount = pointer.arm64e.rebase.next;
					break;
				case Firmware32FixupFormat:
					nextEntryStrideCount = pointer.firmware32.next;
					bind = false;
					break;
				}

				m_logger->LogTrace("Chained Starts: @ 0x%llx ( 0x%llx ) - %d 0x%llx", chainEntryAddress,
					GetStart() + (chainEntryAddress - m_universalImageOffset),
					bind, nextEntryStrideCount);

				if (bind && processBinds)
				{
					m_logger->LogWarn("Chained Starts: Bind pointers not supported in Chained Starts");
					chainEntryAddress += (nextEntryStrideCount * strideSize);
					if (nextEntryStrideCount == 0)
						fixupsDone = true;
					continue;
				}
				else if (!bind)
				{
					uint64_t entryOffset;
					switch (pointerFormat)
					{
					case DYLD_CHAINED_PTR_ARM64E:
					case DYLD_CHAINED_PTR_ARM64E_KERNEL:
					case DYLD_CHAINED_PTR_ARM64E_USERLAND:
					case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
					{
						if (pointer.arm64e.bind.auth)
							entryOffset = pointer.arm64e.authRebase.target;
						else
							entryOffset = pointer.arm64e.rebase.target;

						if ( pointerFormat != DYLD_CHAINED_PTR_ARM64E || pointer.arm64e.bind.auth)
							entryOffset += GetStart();

						break;
					}
					case DYLD_CHAINED_PTR_64:
						entryOffset = pointer.generic64.rebase.target;
						break;
					case DYLD_CHAINED_PTR_64_OFFSET:
						entryOffset = pointer.generic64.rebase.target + GetStart();
						break;
					case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
					case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
						entryOffset = pointer.kernel64.target;
						break;
					case DYLD_CHAINED_PTR_32:
					case DYLD_CHAINED_PTR_32_CACHE:
						entryOffset = pointer.generic32.rebase.target;
						break;
					case DYLD_CHAINED_PTR_32_FIRMWARE:
						entryOffset = pointer.firmware32.target;
						break;
					}

					reloc.address = GetStart() + (chainEntryAddress - m_universalImageOffset);
					DefineRelocation(m_arch, reloc, entryOffset, reloc.address);
					m_logger->LogDebug("Chained Starts: Adding relocated pointer %llx -> %llx", reloc.address, entryOffset);

					if (m_objcProcessor)
					{
						m_objcProcessor->AddRelocatedPointer(reloc.address, entryOffset);
					}
				}

				chainEntryAddress += (nextEntryStrideCount * strideSize);

				if (nextEntryStrideCount == 0)
					fixupsDone = true;
			}
		}
	}
	catch (ReadException&)
	{
		m_logger->LogError("Chained Starts parsing failed");
	}
}


uint64_t MachoView::PerformGetEntryPoint() const
{
	if (m_header.m_entryPoints.size() == 0)
		return 0;

	return m_header.m_entryPoints[0];
}


BNEndianness MachoView::PerformGetDefaultEndianness() const
{
	return LittleEndian;
}


bool MachoView::PerformIsRelocatable() const
{
	return m_relocatable;
}


size_t MachoView::PerformGetAddressSize() const
{
	return m_addressSize;
}


MachoViewType::MachoViewType(): BinaryViewType("Mach-O", "Mach-O")
{
	m_logger = LogRegistry::CreateLogger("BinaryView.MachoViewType");
}


Ref<BinaryView> MachoViewType::Create(BinaryView* data)
{
	try
	{
		return new MachoView("Mach-O", data);
	}
	catch (std::exception& e)
	{
		m_logger->LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}


Ref<BinaryView> MachoViewType::Parse(BinaryView* data)
{
	try
	{
		return new MachoView("Mach-O", data, true);
	}
	catch (std::exception& e)
	{
		m_logger->LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}


bool MachoViewType::IsTypeValidForData(BinaryView* data)
{
	if (!data)
		return false;

	DataBuffer sig = data->ReadBuffer(data->GetStart(), 4);
	if (sig.GetLength() != 4)
		return false;

	uint32_t magic = *(uint32_t*)sig.GetData();
	if (magic == MH_CIGAM || magic == MH_CIGAM_64 || magic == MH_MAGIC || magic == MH_MAGIC_64)
		return true;
	magic = ToBE32(magic);
	if ((magic == FAT_MAGIC) || (magic == FAT_MAGIC_64))
		return true;

	return data->GetLoadSettings(GetName()) ? true : false;
}


uint64_t MachoViewType::ParseHeaders(BinaryView* data, uint64_t imageOffset, mach_header_64& ident, Ref<Architecture>* arch, Ref<Platform>* plat, string& errorMsg)
{
	DataBuffer sig = data->ReadBuffer(imageOffset, 4);
	uint32_t magic = *(uint32_t*)sig.GetData();
	if ((sig.GetLength() != 4) || !(magic == MH_CIGAM || magic == MH_CIGAM_64 || magic == MH_MAGIC || magic == MH_MAGIC_64))
	{
		errorMsg = "invalid signature";
		return 0;
	}

	BinaryReader reader(data);
	reader.SetVirtualBase(imageOffset);
	ident.magic = reader.Read32();

	BNEndianness endianness;
	if (ident.magic == MH_MAGIC || ident.magic == MH_MAGIC_64)
		endianness = LittleEndian;
	else if (ident.magic == MH_CIGAM || ident.magic == MH_CIGAM_64)
		endianness = BigEndian;
	else
	{
		errorMsg = "invalid file class";
		return 0;
	}

	reader.SetEndianness(endianness);
	ident.cputype    = reader.Read32();
	ident.cpusubtype = reader.Read32();
	ident.filetype   = reader.Read32();
	ident.ncmds      = reader.Read32();
	ident.sizeofcmds = reader.Read32();
	ident.flags      = reader.Read32();

	if ((ident.cputype & MachOABIMask) == MachOABI64) // address size == 8
	{
		ident.reserved = reader.Read32();
	}
	if (!(ident.filetype == MH_OBJECT ||
		ident.filetype == MH_EXECUTE ||
		ident.filetype == MH_DYLIB ||
		ident.filetype == MH_DYLINKER ||
		ident.filetype == MH_BUNDLE ||
		ident.filetype == MH_KEXT_BUNDLE ||
		ident.filetype == MH_CORE ||
		ident.filetype == MH_PRELOAD ||
		ident.filetype == MH_DSYM ||
		ident.filetype == MH_FILESET))
	{
		m_logger->LogError("Unhandled Macho file class: 0x%x", ident.filetype);
		errorMsg = "invalid file class";
		return 0;
	}
	uint64_t loadCommandStart = reader.GetOffset();

	uint32_t cmd;
	uint32_t cmdsize;
	MachoPlatform machoPlat = MachoPlatform::MACHO_PLATFORM_MACOS; // Default to macOS.
	// Quickly determine the OS from commands.
	for (uint32_t i = 0; i < ident.ncmds; i++)
	{
		cmd = reader.Read32();
		cmdsize = reader.Read32();
		if (cmd == LC_BUILD_VERSION)
		{
			machoPlat = MachoPlatform(reader.Read32());
			break;
		}
		else if (cmd == LC_VERSION_MIN_MACOSX)
		{
			machoPlat = MachoPlatform(1);
			break;
		}
		else if (cmd == LC_VERSION_MIN_IPHONEOS)
		{
			machoPlat = MachoPlatform(2);
			break;
		}
		else if (cmd == _LC_VERSION_MIN_TVOS)
		{
			machoPlat = MachoPlatform(3);
			break;
		}
		else if (cmd == LC_VERSION_MIN_WATCHOS)
		{
			machoPlat = MachoPlatform(4);
			break;
		}

		reader.SeekRelative(cmdsize - 8);
	}

	map<string, Ref<Metadata>> metadataMap = {
		{"cputype",    new Metadata((uint64_t) ident.cputype)},
		{"cpusubtype", new Metadata((uint64_t) ident.cpusubtype)},
		{"flags",      new Metadata((uint64_t) ident.flags)},
		{"machoplatform",   new Metadata((uint64_t) machoPlat)},
	};

	Ref<Metadata> metadata = new Metadata(metadataMap);

	// retrieve architecture
	// FIXME: Architecture registration methods should perhaps be virtual and take the raw data, or some additional opaque information.
	Ref<Platform> recognizedPlatform = g_machoViewType->RecognizePlatform(ident.cputype, endianness, data, metadata);

	if (recognizedPlatform)
	{
		if (plat)
			*plat = recognizedPlatform;
		if (arch)
			*arch = recognizedPlatform->GetArchitecture();
	}
	else if (arch)
	{
		*arch = g_machoViewType->GetArchitecture(ident.cputype, endianness);
	}

	return loadCommandStart;
}


Ref<Settings> MachoViewType::GetLoadSettingsForData(BinaryView* data)
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

	if (ObjCProcessor::ViewHasObjCMetadata(viewRef))
	{
		settings->RegisterSetting("loader.macho.processObjectiveC",
			R"({
			"title" : "Process Objective-C metadata",
			"type" : "boolean",
			"default" : true,
			"description" : "Processes Objective-C structures, applying method names and types from encoded metadata"
			})");
		Ref<Settings> programSettings = Settings::Instance();
		if (programSettings->Contains("corePlugins.workflows.objc"))
		{
			if (programSettings->Get<bool>("corePlugins.workflows.objc"))
			{
				programSettings->Set("analysis.workflows.functionWorkflow", "core.function.objectiveC", viewRef);
			}
		}
	}
	if (viewRef->GetSectionByName("__cfstring"))
	{
		settings->RegisterSetting("loader.macho.processCFStrings",
			R"({
			"title" : "Process CFString Metadata",
			"type" : "boolean",
			"default" : true,
			"description" : "Processes CoreFoundation strings, applying string values from encoded metadata"
			})");
	}

	// register additional settings
	settings->RegisterSetting("loader.macho.processFunctionStarts",
			R"({
			"title" : "Process Mach-O Function Starts Table",
			"type" : "boolean",
			"default" : true,
			"description" : "Add function starts sourced from the Function Starts table to the core for analysis."
			})");

	if (viewRef->GetSectionByName("__thread_starts"))
	{
		settings->RegisterSetting("loader.macho.rebaseThreadStarts",
				R"({
				"title" : "Rebase Mach-O Kernelcache Thread Starts",
				"type" : "boolean",
				"default" : true,
				"description" : "Add relocation entries to rebase chained thread starts located in the __thread_starts section."
				})");
	}

	// Merge existing load settings if they exist. This allows for the selection of a specific object file from a Mach-O Universal file.
	// The 'Universal' BinaryViewType generates a schema with 'loader.universal.architectures'. This schema contains an appropriate
	// 'Mach-O' load schema for selecting a specific object file. The embedded schema contains 'loader.macho.universalImageOffset'.
	Ref<Settings> loadSettings = viewRef->GetLoadSettings(GetName());
	if (loadSettings && !loadSettings->IsEmpty())
		settings->DeserializeSchema(loadSettings->SerializeSchema());

	return settings;
}


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifdef DEMO_EDITION
	bool MachoPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		InitMachoViewType();
		InitFatMachoViewType();
		InitUniversalViewType();
		return true;
	}
}
