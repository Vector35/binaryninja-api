#include "MachOProcessor.h"
#include "SharedCache.h"

using namespace BinaryNinja;

SharedCacheMachOProcessor::SharedCacheMachOProcessor(Ref<BinaryView> view, std::shared_ptr<VirtualMemory> vm)
{
	m_view = view;
	m_logger = new Logger("SharedCache.MachOProcessor", view->GetFile()->GetSessionId());
	m_vm = std::move(vm);

	// Adjust processor settings.
	if (Ref<Settings> settings = m_view->GetLoadSettings(VIEW_NAME))
	{
		if (settings->Contains("loader.dsc.processFunctionStarts"))
			m_applyFunctions = settings->Get<bool>("loader.dsc.processFunctionStarts", m_view);
	}
}

void SharedCacheMachOProcessor::ApplyHeader(SharedCacheMachOHeader& header)
{
	auto typeLibraryFromName = [&](const std::string& name) -> Ref<TypeLibrary> {
		// Check to see if we have already loaded the type library.
		if (auto typeLib = m_view->GetTypeLibrary(name))
			return typeLib;

		auto typeLibs = m_view->GetDefaultPlatform()->GetTypeLibrariesByName(name);
		if (!typeLibs.empty())
			return typeLibs.front();
		return nullptr;
	};

	// Add a section for the header itself.
	std::string headerSection = fmt::format("{}::__macho_header", header.identifierPrefix);
	// TODO: Support mach_header (non 64bit)
	uint64_t headerSectionSize = sizeof(mach_header_64) + header.ident.sizeofcmds;
	m_view->AddUserSection(headerSection, header.textBase, headerSectionSize, ReadOnlyDataSectionSemantics);

	ApplyHeaderSections(header);
	ApplyHeaderDataVariables(header);

	if (header.linkeditPresent && m_vm->IsAddressMapped(header.linkeditSegment.vmaddr))
	{
		if (m_applyFunctions && header.functionStartsPresent)
		{
			auto targetPlatform = m_view->GetDefaultPlatform();
			auto functions = header.ReadFunctionTable(*m_vm);
			for (const auto& func : functions)
				m_view->AddFunctionForAnalysis(targetPlatform, func, false);
		}

		// Pull the available type library for the image we are loading, so we can apply known types.
		auto typeLib = typeLibraryFromName(header.installName);
		m_view->BeginBulkModifySymbols();

		// TODO: Why does this need to only happen in linkeditSegment?
		// Apply symbols from symbol table.
		if (header.symtab.symoff != 0)
		{
			// Mach-O View symtab processing with
			// a ton of stuff cut out so it can work
			// NOTE: This table is read relative to the link edit segment file base.
			const auto symbols = header.ReadSymbolTable(*m_view, *m_vm);
			for (const auto& sym : symbols)
				ApplySymbol(m_view, typeLib, sym.ToBNSymbol(*m_view));
		}

		// Apply symbols from export trie.
		if (header.exportTriePresent)
		{
			// NOTE: This table is read relative to the link edit segment file base.
			// TODO: Remove this and use the m_symbols in the cache?
			const auto exportSymbols = header.ReadExportSymbolTrie(*m_vm);
			for (const auto& sym : exportSymbols)
				ApplySymbol(m_view, typeLib, sym.ToBNSymbol(*m_view));
		}
		m_view->EndBulkModifySymbols();
	}
}

uint64_t SharedCacheMachOProcessor::ApplyHeaderSections(SharedCacheMachOHeader& header)
{
	auto initSection = [&](const section_64& section, const std::string& sectionName) {
		if (!section.size)
			return false;

		std::string type;
		BNSectionSemantics semantics = DefaultSectionSemantics;
		switch (section.flags & 0xff)
		{
		case S_REGULAR:
			if (section.flags & S_ATTR_PURE_INSTRUCTIONS)
			{
				type = "PURE_CODE";
				semantics = ReadOnlyCodeSectionSemantics;
			}
			else if (section.flags & S_ATTR_SOME_INSTRUCTIONS)
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

		if (strncmp(section.sectname, "__text", sizeof(section.sectname)) == 0)
			semantics = ReadOnlyCodeSectionSemantics;
		if (strncmp(section.sectname, "__const", sizeof(section.sectname)) == 0)
			semantics = ReadOnlyDataSectionSemantics;
		if (strncmp(section.sectname, "__data", sizeof(section.sectname)) == 0)
			semantics = ReadWriteDataSectionSemantics;
		if (strncmp(section.sectname, "__auth_got", sizeof(section.sectname)) == 0)
			semantics = ReadOnlyDataSectionSemantics;
		if (strncmp(section.segname, "__DATA_CONST", sizeof(section.segname)) == 0)
			semantics = ReadOnlyDataSectionSemantics;

		// Typically a view would add auto sections but those won't persist when loading the BNDB.
		// if we want to use an auto section here we would need to allow the core to apply auto sections from the database.
		m_view->AddUserSection(sectionName, section.addr, section.size, semantics, type, section.align);

		return true;
	};

	uint64_t addedSections = 0;
	for (size_t i = 0; i < header.sections.size() && i < header.sectionNames.size(); i++)
	{
		if (initSection(header.sections[i], header.sectionNames[i]))
			addedSections++;
	}
	return addedSections;
}

void SharedCacheMachOProcessor::ApplyHeaderDataVariables(SharedCacheMachOHeader& header)
{
	// TODO: By using a binary reader we assume the sections have all been mapped.
	// TODO: Maybe we should just use the virtual memory reader...
	// TODO: We can define symbols and data variables even if there is no backing region FWIW
	BinaryReader reader(m_view);
	// TODO: Do we support non 64 bit header?
	reader.Seek(header.textBase + sizeof(mach_header_64));

	m_view->DefineDataVariable(header.textBase, Type::NamedType(m_view, QualifiedName("mach_header_64")));
	m_view->DefineAutoSymbol(
		new Symbol(DataSymbol, "__macho_header::" + header.identifierPrefix, header.textBase, LocalBinding));

	auto applyLoadCommand = [&](uint64_t cmdAddr, const load_command& load) {
		switch (load.cmd)
		{
		case LC_SEGMENT:
		{
			m_view->DefineDataVariable(cmdAddr, Type::NamedType(m_view, QualifiedName("segment_command")));
			reader.SeekRelative(5 * 8);
			size_t numSections = reader.Read32();
			reader.SeekRelative(4);
			for (size_t j = 0; j < numSections; j++)
			{
				m_view->DefineDataVariable(reader.GetOffset(), Type::NamedType(m_view, QualifiedName("section")));
				auto sectionSymName =
					fmt::format("__macho_section::{}_[{}]", header.identifierPrefix, std::to_string(j));
				auto sectionSym = new Symbol(DataSymbol, sectionSymName, reader.GetOffset(), LocalBinding);
				m_view->DefineAutoSymbol(sectionSym);
				reader.SeekRelative((8 * 8) + 4);
			}
			break;
		}
		case LC_SEGMENT_64:
		{
			m_view->DefineDataVariable(cmdAddr, Type::NamedType(m_view, QualifiedName("segment_command_64")));
			reader.SeekRelative(7 * 8);
			size_t numSections = reader.Read32();
			reader.SeekRelative(4);
			for (size_t j = 0; j < numSections; j++)
			{
				m_view->DefineDataVariable(reader.GetOffset(), Type::NamedType(m_view, QualifiedName("section_64")));
				auto sectionSymName =
					fmt::format("__macho_section_64::{}_[{}]", header.identifierPrefix, std::to_string(j));
				auto sectionSym = new Symbol(DataSymbol, sectionSymName, reader.GetOffset(), LocalBinding);
				m_view->DefineAutoSymbol(sectionSym);
				reader.SeekRelative(10 * 8);
			}
			break;
		}
		case LC_SYMTAB:
			m_view->DefineDataVariable(cmdAddr, Type::NamedType(m_view, QualifiedName("symtab")));
			break;
		case LC_DYSYMTAB:
			m_view->DefineDataVariable(cmdAddr, Type::NamedType(m_view, QualifiedName("dysymtab")));
			break;
		case LC_UUID:
			m_view->DefineDataVariable(cmdAddr, Type::NamedType(m_view, QualifiedName("uuid")));
			break;
		case LC_ID_DYLIB:
		case LC_LOAD_DYLIB:
		case LC_REEXPORT_DYLIB:
		case LC_LOAD_WEAK_DYLIB:
		case LC_LOAD_UPWARD_DYLIB:
			m_view->DefineDataVariable(cmdAddr, Type::NamedType(m_view, QualifiedName("dylib_command")));
			if (load.cmdsize - 24 <= 150)
				m_view->DefineDataVariable(
					cmdAddr + 24, Type::ArrayType(Type::IntegerType(1, true), load.cmdsize - 24));
			break;
		case LC_CODE_SIGNATURE:
		case LC_SEGMENT_SPLIT_INFO:
		case LC_FUNCTION_STARTS:
		case LC_DATA_IN_CODE:
		case LC_DYLIB_CODE_SIGN_DRS:
		case LC_DYLD_EXPORTS_TRIE:
		case LC_DYLD_CHAINED_FIXUPS:
			m_view->DefineDataVariable(cmdAddr, Type::NamedType(m_view, QualifiedName("linkedit_data")));
			break;
		case LC_ENCRYPTION_INFO:
			m_view->DefineDataVariable(cmdAddr, Type::NamedType(m_view, QualifiedName("encryption_info")));
			break;
		case LC_VERSION_MIN_MACOSX:
		case LC_VERSION_MIN_IPHONEOS:
			m_view->DefineDataVariable(cmdAddr, Type::NamedType(m_view, QualifiedName("version_min")));
			break;
		case LC_DYLD_INFO:
		case LC_DYLD_INFO_ONLY:
			m_view->DefineDataVariable(cmdAddr, Type::NamedType(m_view, QualifiedName("dyld_info")));
			break;
		default:
			m_view->DefineDataVariable(cmdAddr, Type::NamedType(m_view, QualifiedName("load_command")));
			break;
		}
	};

	try
	{
		for (size_t i = 0; i < header.ident.ncmds; i++)
		{
			load_command load {};
			uint64_t curOffset = reader.GetOffset();
			load.cmd = reader.Read32();
			load.cmdsize = reader.Read32();

			applyLoadCommand(curOffset, load);
			m_view->DefineAutoSymbol(new Symbol(DataSymbol,
				"__macho_load_command::" + header.identifierPrefix + "_[" + std::to_string(i) + "]", curOffset,
				LocalBinding));

			uint64_t nextOffset = curOffset + load.cmdsize;
			reader.Seek(nextOffset);
		}
	}
	catch (ReadException&)
	{
		m_logger->LogError("Error when applying Mach-O header types at %llx", header.textBase);
	}
}
