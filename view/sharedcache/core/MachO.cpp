#include "MachO.h"
#include "Utility.h"

#include "SharedCache.h"
#include "VirtualMemory.h"

using namespace BinaryNinja;

std::vector<uint64_t> SharedCacheMachOHeader::ReadFunctionTable(VirtualMemory& vm) const
{
	// NOTE: The funcoff is relative to the file of the linkedit segment.
	uint64_t funcStartsAddress = GetLinkEditFileBase() + functionStarts.funcoff;
	auto funcStarts = vm.ReadBuffer(funcStartsAddress, functionStarts.funcsize);
	uint64_t curfunc = textBase;
	uint64_t curOffset = 0;

	std::vector<uint64_t> functionTable = {};
	auto current = static_cast<const uint8_t*>(funcStarts.GetData());
	auto end = current + funcStarts.GetLength();
	while (current != end)
	{
		curOffset = readLEB128(current, end);
		// TODO: Verify this is the correct behavior.
		// Skip unmapped functions.
		if (curOffset == 0 || !vm.IsAddressMapped(curfunc))
			continue;
		curfunc += curOffset;
		uint64_t target = curfunc;
		functionTable.push_back(target);
	}
	return functionTable;
}

std::optional<SharedCacheMachOHeader> SharedCacheMachOHeader::ParseHeaderForAddress(
	std::shared_ptr<VirtualMemory> vm, uint64_t address, const std::string& imagePath)
{
	// Sanity check to make sure that the header is mapped.
	// This should really only fail if we didn't grab all the required entries.
	if (!vm->IsAddressMapped(address))
		return std::nullopt;

	SharedCacheMachOHeader header;

	header.textBase = address;
	header.installName = imagePath;
	// The identifierPrefix is used for the display of the image name in the sections and segments.
	header.identifierPrefix = BaseFileName(imagePath);

	std::string errorMsg;
	VirtualMemoryReader reader(vm);
	reader.Seek(address);

	header.ident.magic = reader.ReadUInt32();

	BNEndianness endianness;
	switch (header.ident.magic)
	{
	case MH_MAGIC:
	case MH_MAGIC_64:
		endianness = LittleEndian;
		break;
	case MH_CIGAM:
	case MH_CIGAM_64:
		endianness = BigEndian;
		break;
	default:
		return {};
	}

	reader.SetEndianness(endianness);
	header.ident.cputype = reader.ReadUInt32();
	header.ident.cpusubtype = reader.ReadUInt32();
	header.ident.filetype = reader.ReadUInt32();
	header.ident.ncmds = reader.ReadUInt32();
	header.ident.sizeofcmds = reader.ReadUInt32();
	header.ident.flags = reader.ReadUInt32();
	if ((header.ident.cputype & MachOABIMask) == MachOABI64)  // address size == 8
	{
		header.ident.reserved = reader.ReadUInt32();
	}
	header.loadCommandOffset = reader.GetOffset();

	bool first = true;
	// Parse segment commands
	try
	{
		for (size_t i = 0; i < header.ident.ncmds; i++)
		{
			// BNLogInfo("of 0x%llx", reader.GetOffset());
			load_command load;
			segment_command_64 segment64;
			section_64 sect = {};
			size_t curOffset = reader.GetOffset();
			load.cmd = reader.ReadUInt32();
			load.cmdsize = reader.ReadUInt32();
			size_t nextOffset = curOffset + load.cmdsize;
			if (load.cmdsize < sizeof(load_command))
				return {};

			switch (load.cmd)
			{
			case LC_MAIN:
			{
				uint64_t entryPoint = reader.ReadUInt64();
				header.entryPoints.push_back({entryPoint, true});
				(void)reader.ReadUInt64();  // Stack start
				break;
			}
			case LC_SEGMENT:  // map the 32bit version to 64 bits
				segment64.cmd = LC_SEGMENT_64;
				reader.Read(&segment64.segname, 16);
				segment64.vmaddr = reader.ReadUInt32();
				segment64.vmsize = reader.ReadUInt32();
				segment64.fileoff = reader.ReadUInt32();
				segment64.filesize = reader.ReadUInt32();
				segment64.maxprot = reader.ReadUInt32();
				segment64.initprot = reader.ReadUInt32();
				segment64.nsects = reader.ReadUInt32();
				segment64.flags = reader.ReadUInt32();
				if (first)
				{
					if (!((header.ident.flags & MH_SPLIT_SEGS) || header.ident.cputype == MACHO_CPU_TYPE_X86_64)
						|| (segment64.flags & MACHO_VM_PROT_WRITE))
					{
						header.relocationBase = segment64.vmaddr;
						first = false;
					}
				}
				for (size_t j = 0; j < segment64.nsects; j++)
				{
					reader.Read(&sect.sectname, 16);
					reader.Read(&sect.segname, 16);
					sect.addr = reader.ReadUInt32();
					sect.size = reader.ReadUInt32();
					sect.offset = reader.ReadUInt32();
					sect.align = reader.ReadUInt32();
					sect.reloff = reader.ReadUInt32();
					sect.nreloc = reader.ReadUInt32();
					sect.flags = reader.ReadUInt32();
					sect.reserved1 = reader.ReadUInt32();
					sect.reserved2 = reader.ReadUInt32();
					// if the segment isn't mapped into virtual memory don't add the corresponding sections.
					if (segment64.vmsize > 0)
					{
						header.sections.push_back(sect);
					}
					if (!strncmp(sect.sectname, "__mod_init_func", 15))
						header.moduleInitSections.push_back(sect);
					if ((sect.flags & (S_ATTR_SELF_MODIFYING_CODE | S_SYMBOL_STUBS))
						== (S_ATTR_SELF_MODIFYING_CODE | S_SYMBOL_STUBS))
						header.symbolStubSections.push_back(sect);
					if ((sect.flags & S_NON_LAZY_SYMBOL_POINTERS) == S_NON_LAZY_SYMBOL_POINTERS)
						header.symbolPointerSections.push_back(sect);
					if ((sect.flags & S_LAZY_SYMBOL_POINTERS) == S_LAZY_SYMBOL_POINTERS)
						header.symbolPointerSections.push_back(sect);
				}
				header.segments.push_back(segment64);
				break;
			case LC_SEGMENT_64:
				segment64.cmd = LC_SEGMENT_64;
				reader.Read(&segment64.segname, 16);
				segment64.vmaddr = reader.ReadUInt64();
				segment64.vmsize = reader.ReadUInt64();
				segment64.fileoff = reader.ReadUInt64();
				segment64.filesize = reader.ReadUInt64();
				segment64.maxprot = reader.ReadUInt32();
				segment64.initprot = reader.ReadUInt32();
				segment64.nsects = reader.ReadUInt32();
				segment64.flags = reader.ReadUInt32();
				if (strncmp(segment64.segname, "__LINKEDIT", 10) == 0)
				{
					header.linkeditSegment = segment64;
					header.linkeditPresent = true;
				}
				if (first)
				{
					if (!((header.ident.flags & MH_SPLIT_SEGS) || header.ident.cputype == MACHO_CPU_TYPE_X86_64)
						|| (segment64.flags & MACHO_VM_PROT_WRITE))
					{
						header.relocationBase = segment64.vmaddr;
						first = false;
					}
				}
				for (size_t j = 0; j < segment64.nsects; j++)
				{
					reader.Read(&sect.sectname, 16);
					reader.Read(&sect.segname, 16);
					sect.addr = reader.ReadUInt64();
					sect.size = reader.ReadUInt64();
					sect.offset = reader.ReadUInt32();
					sect.align = reader.ReadUInt32();
					sect.reloff = reader.ReadUInt32();
					sect.nreloc = reader.ReadUInt32();
					sect.flags = reader.ReadUInt32();
					sect.reserved1 = reader.ReadUInt32();
					sect.reserved2 = reader.ReadUInt32();
					sect.reserved3 = reader.ReadUInt32();
					// if the segment isn't mapped into virtual memory don't add the corresponding sections.
					if (segment64.vmsize > 0)
					{
						header.sections.push_back(sect);
					}

					if (!strncmp(sect.sectname, "__mod_init_func", 15))
						header.moduleInitSections.push_back(sect);
					if ((sect.flags & (S_ATTR_SELF_MODIFYING_CODE | S_SYMBOL_STUBS))
						== (S_ATTR_SELF_MODIFYING_CODE | S_SYMBOL_STUBS))
						header.symbolStubSections.push_back(sect);
					if ((sect.flags & S_NON_LAZY_SYMBOL_POINTERS) == S_NON_LAZY_SYMBOL_POINTERS)
						header.symbolPointerSections.push_back(sect);
					if ((sect.flags & S_LAZY_SYMBOL_POINTERS) == S_LAZY_SYMBOL_POINTERS)
						header.symbolPointerSections.push_back(sect);
				}
				header.segments.push_back(segment64);
				break;
			case LC_ROUTINES:  // map the 32bit version to 64bits
				header.routines64.cmd = LC_ROUTINES_64;
				header.routines64.init_address = reader.ReadUInt32();
				header.routines64.init_module = reader.ReadUInt32();
				header.routines64.reserved1 = reader.ReadUInt32();
				header.routines64.reserved2 = reader.ReadUInt32();
				header.routines64.reserved3 = reader.ReadUInt32();
				header.routines64.reserved4 = reader.ReadUInt32();
				header.routines64.reserved5 = reader.ReadUInt32();
				header.routines64.reserved6 = reader.ReadUInt32();
				header.routinesPresent = true;
				break;
			case LC_ROUTINES_64:
				header.routines64.cmd = LC_ROUTINES_64;
				header.routines64.init_address = reader.ReadUInt64();
				header.routines64.init_module = reader.ReadUInt64();
				header.routines64.reserved1 = reader.ReadUInt64();
				header.routines64.reserved2 = reader.ReadUInt64();
				header.routines64.reserved3 = reader.ReadUInt64();
				header.routines64.reserved4 = reader.ReadUInt64();
				header.routines64.reserved5 = reader.ReadUInt64();
				header.routines64.reserved6 = reader.ReadUInt64();
				header.routinesPresent = true;
				break;
			case LC_FUNCTION_STARTS:
				header.functionStarts.funcoff = reader.ReadUInt32();
				header.functionStarts.funcsize = reader.ReadUInt32();
				header.functionStartsPresent = true;
				break;
			case LC_SYMTAB:
				header.symtab.symoff = reader.ReadUInt32();
				header.symtab.nsyms = reader.ReadUInt32();
				header.symtab.stroff = reader.ReadUInt32();
				header.symtab.strsize = reader.ReadUInt32();
				break;
			case LC_DYSYMTAB:
				header.dysymtab.ilocalsym = reader.ReadUInt32();
				header.dysymtab.nlocalsym = reader.ReadUInt32();
				header.dysymtab.iextdefsym = reader.ReadUInt32();
				header.dysymtab.nextdefsym = reader.ReadUInt32();
				header.dysymtab.iundefsym = reader.ReadUInt32();
				header.dysymtab.nundefsym = reader.ReadUInt32();
				header.dysymtab.tocoff = reader.ReadUInt32();
				header.dysymtab.ntoc = reader.ReadUInt32();
				header.dysymtab.modtaboff = reader.ReadUInt32();
				header.dysymtab.nmodtab = reader.ReadUInt32();
				header.dysymtab.extrefsymoff = reader.ReadUInt32();
				header.dysymtab.nextrefsyms = reader.ReadUInt32();
				header.dysymtab.indirectsymoff = reader.ReadUInt32();
				header.dysymtab.nindirectsyms = reader.ReadUInt32();
				header.dysymtab.extreloff = reader.ReadUInt32();
				header.dysymtab.nextrel = reader.ReadUInt32();
				header.dysymtab.locreloff = reader.ReadUInt32();
				header.dysymtab.nlocrel = reader.ReadUInt32();
				header.dysymPresent = true;
				break;
			case LC_DYLD_CHAINED_FIXUPS:
				header.chainedFixups.dataoff = reader.ReadUInt32();
				header.chainedFixups.datasize = reader.ReadUInt32();
				header.chainedFixupsPresent = true;
				break;
			case LC_DYLD_INFO:
			case LC_DYLD_INFO_ONLY:
				header.dyldInfo.rebase_off = reader.ReadUInt32();
				header.dyldInfo.rebase_size = reader.ReadUInt32();
				header.dyldInfo.bind_off = reader.ReadUInt32();
				header.dyldInfo.bind_size = reader.ReadUInt32();
				header.dyldInfo.weak_bind_off = reader.ReadUInt32();
				header.dyldInfo.weak_bind_size = reader.ReadUInt32();
				header.dyldInfo.lazy_bind_off = reader.ReadUInt32();
				header.dyldInfo.lazy_bind_size = reader.ReadUInt32();
				header.dyldInfo.export_off = reader.ReadUInt32();
				header.dyldInfo.export_size = reader.ReadUInt32();
				header.exportTrie.dataoff = header.dyldInfo.export_off;
				header.exportTrie.datasize = header.dyldInfo.export_size;
				header.exportTriePresent = true;
				header.dyldInfoPresent = true;
				break;
			case LC_DYLD_EXPORTS_TRIE:
				header.exportTrie.dataoff = reader.ReadUInt32();
				header.exportTrie.datasize = reader.ReadUInt32();
				header.exportTriePresent = true;
				break;
			case LC_THREAD:
			case LC_UNIXTHREAD:
				/*while (reader.GetOffset() < nextOffset)
				{

				    thread_command thread;
				    thread.flavor = reader.ReadUInt32();
				    thread.count = reader.ReadUInt32();
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
				            header.entryPoints.push_back({reader.ReadUInt32(), false});
				            (void)reader.ReadUInt32();
				            (void)reader.ReadUInt32();
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
				            header.entryPoints.push_back({reader.ReadUInt64(), false});
				            (void)reader.ReadUInt64();
				            (void)reader.ReadUInt64(); // Stack start
				            (void)reader.Read(&thread.stateppc64.r1, sizeof(thread.stateppc64) - (3 * 8));
				            break;
				        default:
				            m_logger->LogError("Unknown archid: %x", m_archId);
				    }

				}*/
				break;
			case LC_LOAD_DYLIB:
			{
				uint32_t offset = reader.ReadUInt32();
				if (offset < nextOffset)
				{
					reader.Seek(curOffset + offset);
					std::string libname = reader.ReadCString(reader.GetOffset());
					header.dylibs.push_back(libname);
				}
			}
			break;
			case LC_BUILD_VERSION:
			{
				// m_logger->LogDebug("LC_BUILD_VERSION:");
				header.buildVersion.platform = reader.ReadUInt32();
				header.buildVersion.minos = reader.ReadUInt32();
				header.buildVersion.sdk = reader.ReadUInt32();
				header.buildVersion.ntools = reader.ReadUInt32();
				// m_logger->LogDebug("Platform: %s", BuildPlatformToString(header.buildVersion.platform).c_str());
				// m_logger->LogDebug("MinOS: %s", BuildToolVersionToString(header.buildVersion.minos).c_str());
				// m_logger->LogDebug("SDK: %s", BuildToolVersionToString(header.buildVersion.sdk).c_str());
				for (uint32_t j = 0; (i < header.buildVersion.ntools) && (j < 10); j++)
				{
					uint32_t tool = reader.ReadUInt32();
					uint32_t version = reader.ReadUInt32();
					header.buildToolVersions.push_back({tool, version});
					// m_logger->LogDebug("Build Tool: %s: %s", BuildToolToString(tool).c_str(),
					// BuildToolVersionToString(version).c_str());
				}
				break;
			}
			case LC_FILESET_ENTRY:
			{
				throw ReadException();
			}
			default:
				// m_logger->LogDebug("Unhandled command: %s : %" PRIu32 "\n", CommandToString(load.cmd).c_str(),
				// load.cmdsize);
				break;
			}
			if (reader.GetOffset() != nextOffset)
			{
				// m_logger->LogDebug("Didn't parse load command: %s fully %" PRIx64 ":%" PRIxPTR,
				// CommandToString(load.cmd).c_str(), reader.GetOffset(), nextOffset);
			}
			reader.Seek(nextOffset);
		}

		for (auto& section : header.sections)
		{
			char sectionName[17];
			memcpy(sectionName, section.sectname, sizeof(section.sectname));
			sectionName[16] = 0;
			header.sectionNames.push_back(header.identifierPrefix + "::" + sectionName);
		}
	}
	catch (ReadException&)
	{
		return {};
	}

	return header;
}

// TODO: Support reading from .symbols file.
// TODO: Replace view with address size?
std::vector<CacheSymbol> SharedCacheMachOHeader::ReadSymbolTable(BinaryView& view, VirtualMemory& vm) const
{
	auto addressSize = view.GetAddressSize();
	// NOTE: The symbol table will exist within the link edit segment, the table offsets are relative to the file not
	// the linkedit segment.
	uint64_t symbolsAddress = GetLinkEditFileBase() + symtab.symoff;
	uint64_t stringsAddress = GetLinkEditFileBase() + symtab.stroff;

	// TODO: This needs to be passed in as an optional argument.
	// TODO: Sometimes symbol tables are shared and we have to offset into the table for a specific header.
	// TODO: The "shared" symbol tables are stored in .symbols files.
	int nlistStartIndex = 0;

	std::vector<CacheSymbol> symbolList;
	for (uint64_t i = 0; i < symtab.nsyms; i++)
	{
		uint64_t entryIndex = (nlistStartIndex + i);

		nlist_64 nlist = {};
		if (addressSize == 4)
		{
			// 32-bit DSC
			struct nlist nlist32 = {};
			vm.Read(&nlist, symbolsAddress + (entryIndex * sizeof(nlist32)), sizeof(nlist32));
			nlist.n_strx = nlist32.n_strx;
			nlist.n_type = nlist32.n_type;
			nlist.n_sect = nlist32.n_sect;
			nlist.n_desc = nlist32.n_desc;
			nlist.n_value = nlist32.n_value;
		}
		else
		{
			// 64-bit DSC
			vm.Read(&nlist, symbolsAddress + (entryIndex * sizeof(nlist)), sizeof(nlist));
		}

		auto symbolAddress = nlist.n_value;
		if (((nlist.n_type & N_TYPE) == N_INDR) || symbolAddress == 0)
			continue;

		if (nlist.n_strx >= symtab.strsize)
		{
			// TODO: where logger?
			LogError(
				"Symbol entry at index %llu has a string offset of %u which is outside the strings buffer of size %u "
			    "for symbol table %x",
				entryIndex, nlist.n_strx, symtab.strsize, symtab.stroff);
			continue;
		}

		std::string symbolName = vm.ReadCString(stringsAddress + nlist.n_strx);
		if (symbolName == "<redacted>")
			continue;

		std::optional<BNSymbolType> symbolType;
		if ((nlist.n_type & N_TYPE) == N_SECT && nlist.n_sect > 0 && (size_t)(nlist.n_sect - 1) < sections.size())
			symbolType = DataSymbol;
		else if ((nlist.n_type & N_TYPE) == N_ABS)
			symbolType = DataSymbol;
		else if ((nlist.n_type & N_EXT))
			symbolType = ExternalSymbol;

		if (!symbolType.has_value())
		{
			// TODO: Where logger?
			LogError("Symbol %s at address %llx has unknown symbol type", symbolName.c_str(), symbolAddress);
			continue;
		}

		std::optional<uint32_t> flags;
		for (auto s : sections)
		{
			if (s.addr <= symbolAddress && symbolAddress < s.addr + s.size)
			{
				// First section to contain the address we will use its flags.
				flags = s.flags;
				break;
			}
		}

		if (symbolType != ExternalSymbol)
		{
			if (!flags.has_value())
			{
				// TODO: where logger?
				LogError("Symbol %s at address %llx is not in any section", symbolName.c_str(), symbolAddress);
				continue;
			}

			if ((flags.value() & S_ATTR_PURE_INSTRUCTIONS) == S_ATTR_PURE_INSTRUCTIONS
				|| (flags.value() & S_ATTR_SOME_INSTRUCTIONS) == S_ATTR_SOME_INSTRUCTIONS)
				symbolType = FunctionSymbol;
			else
				symbolType = DataSymbol;
		}
		if ((nlist.n_desc & N_ARM_THUMB_DEF) == N_ARM_THUMB_DEF)
			symbolAddress++;

		CacheSymbol symbol;
		symbol.address = symbolAddress;
		symbol.name = std::move(symbolName);
		symbol.type = symbolType.value();
		symbolList.emplace_back(symbol);
	}

	return symbolList;
}

std::optional<CacheSymbol> SharedCacheMachOHeader::AddExportTerminalSymbol(
	const std::string& symbolName, const uint8_t* current, const uint8_t* end) const
{
	uint64_t symbolFlags = readValidULEB128(current, end);
	if (symbolFlags & EXPORT_SYMBOL_FLAGS_REEXPORT)
		return std::nullopt;

	uint64_t imageOffset = readValidULEB128(current, end);
	uint64_t symbolAddress = textBase + imageOffset;
	if (symbolName.empty() || symbolAddress == 0)
		return std::nullopt;

	// Tries to get the symbol type based off the section containing it.
	auto sectionSymbolType = [&]() -> BNSymbolType {
		uint32_t sectionFlags = 0;
		for (const auto& section : sections)
		{
			if (symbolAddress >= section.addr && symbolAddress < section.addr + section.size)
			{
				// Take the flags from the first containing section.
				sectionFlags = section.flags;
				break;
			}
		}

		// TODO: Is this enough to determine a function symbol?
		// TODO: Might be the cause of https://github.com/Vector35/binaryninja-api/issues/6526
		// Check the sections flags to see if we actually have a function symbol instead.
		if (sectionFlags & S_ATTR_PURE_INSTRUCTIONS || sectionFlags & S_ATTR_SOME_INSTRUCTIONS)
			return FunctionSymbol;

		// By default, just return data symbol.
		return DataSymbol;
	};

	switch (symbolFlags & EXPORT_SYMBOL_FLAGS_KIND_MASK)
	{
	case EXPORT_SYMBOL_FLAGS_KIND_REGULAR:
	case EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL:
		return CacheSymbol(sectionSymbolType(), symbolAddress, symbolName);
	case EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE:
		return CacheSymbol(DataSymbol, symbolAddress, symbolName);
	default:
		LogWarn("Unhandled export symbol kind: %llx", symbolFlags & EXPORT_SYMBOL_FLAGS_KIND_MASK);
		return std::nullopt;
	}
}

// TODO: This is like 90% of the runtime.
bool SharedCacheMachOHeader::ProcessLinkEditTrie(std::vector<CacheSymbol>& symbols, const std::string& currentText,
	const uint8_t* begin, const uint8_t* current, const uint8_t* end) const
{
	if (current >= end)
		return false;

	uint64_t terminalSize = readValidULEB128(current, end);
	const uint8_t* child = current + terminalSize;

	// The terminal is an export symbol.
	if (terminalSize != 0)
	{
		// Add the export symbol is applicable.
		auto symbol = AddExportTerminalSymbol(currentText, current, end);
		if (symbol.has_value())
			symbols.push_back(*symbol);
	}

	// TODO: Make this look better
	current = child;
	uint8_t childCount = *current++;
	std::string childText = currentText;
	for (uint8_t i = 0; i < childCount; ++i)
	{
		if (current >= end)
			return false;
		const auto it = std::find(current, end, 0);
		childText.append(current, it);
		current = it + 1;
		if (current >= end)
			return false;
		const auto next = readValidULEB128(current, end);
		if (next == 0)
			return false;
		if (!ProcessLinkEditTrie(symbols, childText, begin, begin + next, end))
			return false;
		childText.resize(currentText.size());
	}

	return true;
}

std::vector<CacheSymbol> SharedCacheMachOHeader::ReadExportSymbolTrie(VirtualMemory& vm) const
{
	if (exportTrie.datasize == 0)
		return {};

	uint64_t exportTrieAddress = GetLinkEditFileBase() + exportTrie.dataoff;
	std::vector<CacheSymbol> symbols = {};
	try
	{
		auto [begin, end] = vm.ReadSpan(exportTrieAddress, exportTrie.datasize);
		ProcessLinkEditTrie(symbols, "", begin, begin, end);
	}
	catch (std::exception& e)
	{
		BNLogError("Failed to read Export Trie: %s", e.what());
	}
	return symbols;
}
