#include "macho/types.h"

#include <initializer_list>
#include <stdlib.h>

using namespace BinaryNinja;

namespace BinaryNinja::MachO {

namespace {
	Ref<Type> BuildEnum(Ref<BinaryView> view, const std::string& name, size_t width,
		std::initializer_list<std::pair<std::string_view, uint32_t>> values)
	{
		EnumerationBuilder builder;
		for (const auto& value : values)
			builder.AddMemberWithValue(std::string(value.first), value.second);
		Ref<Type> type = Type::EnumerationType(nullptr, builder.Finalize(), width, false);
		QualifiedName qualName(name);
		std::string typeId = Type::GenerateAutoTypeId("macho", qualName);
		return Type::NamedType(view, view->DefineType(typeId, qualName, type));
	}

	Ref<Type> BuildStruct(Ref<BinaryView> view, const std::string& name, bool packed,
		std::initializer_list<std::pair<std::string_view, Ref<Type>>> members)
	{
		StructureBuilder builder;
		builder.SetPacked(packed);
		for (const auto& member : members)
			builder.AddMember(member.second, std::string(member.first));
		Ref<Type> type = Type::StructureType(builder.Finalize());
		QualifiedName qualName(name);
		std::string typeId = Type::GenerateAutoTypeId("macho", qualName);
		return Type::NamedType(view, view->DefineType(typeId, qualName, type));
	}

}  // namespace

void CreateHeaderTypes(Ref<BinaryView> view)
{
	auto cpuTypeEnum = BuildEnum(view, "cpu_type_t", 4,
		{
			// clang-format off
			{"CPU_TYPE_ANY", MACHO_CPU_TYPE_ANY},
			{"CPU_TYPE_VAX", MACHO_CPU_TYPE_VAX},
			{"CPU_TYPE_MC680x0", MACHO_CPU_TYPE_MC680x0},
			{"CPU_TYPE_X86", MACHO_CPU_TYPE_X86},
			{"CPU_TYPE_X86_64", MACHO_CPU_TYPE_X86_64},
			{"CPU_TYPE_MIPS", MACHO_CPU_TYPE_MIPS},
			{"CPU_TYPE_MC98000", MACHO_CPU_TYPE_MC98000},
			{"CPU_TYPE_HPPA", MACHO_CPU_TYPE_HPPA},
			{"CPU_TYPE_ARM", MACHO_CPU_TYPE_ARM},
			{"CPU_TYPE_ARM64", MACHO_CPU_TYPE_ARM64},
			{"CPU_TYPE_ARM64_32", MACHO_CPU_TYPE_ARM64_32},
			{"CPU_TYPE_MC88000", MACHO_CPU_TYPE_MC88000},
			{"CPU_TYPE_SPARC", MACHO_CPU_TYPE_SPARC},
			{"CPU_TYPE_I860", MACHO_CPU_TYPE_I860},
			{"CPU_TYPE_ALPHA", MACHO_CPU_TYPE_ALPHA},
			{"CPU_TYPE_POWERPC", MACHO_CPU_TYPE_POWERPC},
			{"CPU_TYPE_POWERPC64", MACHO_CPU_TYPE_POWERPC64}
			// clang-format on
		});

	auto cpuSubTypeEnum = BuildEnum(view, "cpu_subtype_t", 4,
		{
			// clang-format off
			{"CPU_SUBTYPE_MASK", MACHO_CPU_SUBTYPE_MASK},
			{"CPU_SUBTYPE_LIB64", MACHO_CPU_SUBTYPE_LIB64},
			{"CPU_SUBTYPE_INTEL_ALL", MACHO_CPU_SUBTYPE_I386_ALL},
			{"CPU_SUBTYPE_X86_ALL", MACHO_CPU_SUBTYPE_X86_ALL},
			{"CPU_SUBTYPE_X86_ARCH1", MACHO_CPU_SUBTYPE_X86_ARCH1},
			{"CPU_SUBTYPE_X86_64_ALL", MACHO_CPU_SUBTYPE_X86_64_ALL},
			{"CPU_SUBTYPE_X86_64_H", MACHO_CPU_SUBTYPE_X86_64_H},
			{"CPU_SUBTYPE_ARM_ALL", MACHO_CPU_SUBTYPE_ARM_ALL},
			{"CPU_SUBTYPE_ARM_V4T", MACHO_CPU_SUBTYPE_ARM_V4T},
			{"CPU_SUBTYPE_ARM_V6", MACHO_CPU_SUBTYPE_ARM_V6},
			{"CPU_SUBTYPE_ARM_V5TEJ", MACHO_CPU_SUBTYPE_ARM_V5TEJ},
			{"CPU_SUBTYPE_ARM_XSCALE", MACHO_CPU_SUBTYPE_ARM_XSCALE},
			{"CPU_SUBTYPE_ARM_V7", MACHO_CPU_SUBTYPE_ARM_V7},
			{"CPU_SUBTYPE_ARM_V7F", MACHO_CPU_SUBTYPE_ARM_V7F},
			{"CPU_SUBTYPE_ARM_V7S", MACHO_CPU_SUBTYPE_ARM_V7S},
			{"CPU_SUBTYPE_ARM_V7K", MACHO_CPU_SUBTYPE_ARM_V7K},
			{"CPU_SUBTYPE_ARM_V8", MACHO_CPU_SUBTYPE_ARM_V8},
			{"CPU_SUBTYPE_ARM_V6M", MACHO_CPU_SUBTYPE_ARM_V6M},
			{"CPU_SUBTYPE_ARM_V7M", MACHO_CPU_SUBTYPE_ARM_V7M},
			{"CPU_SUBTYPE_ARM_V7EM", MACHO_CPU_SUBTYPE_ARM_V7EM},
			{"CPU_SUBTYPE_ARM64_ALL", MACHO_CPU_SUBTYPE_ARM64_ALL},
			{"CPU_SUBTYPE_ARM64_V8", MACHO_CPU_SUBTYPE_ARM64_V8},
			{"CPU_SUBTYPE_ARM64E", MACHO_CPU_SUBTYPE_ARM64E},
			{"CPU_SUBTYPE_ARM64_32_ALL", MACHO_CPU_SUBTYPE_ARM64_32_ALL},
			{"CPU_SUBTYPE_ARM64_32_V8", MACHO_CPU_SUBTYPE_ARM64_32_V8},
			{"CPU_SUBTYPE_POWERPC_ALL", MACHO_CPU_SUBTYPE_POWERPC_ALL},
			{"CPU_SUBTYPE_POWERPC_601", MACHO_CPU_SUBTYPE_POWERPC_601},
			{"CPU_SUBTYPE_POWERPC_602", MACHO_CPU_SUBTYPE_POWERPC_602},
			{"CPU_SUBTYPE_POWERPC_603", MACHO_CPU_SUBTYPE_POWERPC_603},
			{"CPU_SUBTYPE_POWERPC_603e", MACHO_CPU_SUBTYPE_POWERPC_603e},
			{"CPU_SUBTYPE_POWERPC_603ev", MACHO_CPU_SUBTYPE_POWERPC_603ev},
			{"CPU_SUBTYPE_POWERPC_604", MACHO_CPU_SUBTYPE_POWERPC_604},
			{"CPU_SUBTYPE_POWERPC_604e", MACHO_CPU_SUBTYPE_POWERPC_604e},
			{"CPU_SUBTYPE_POWERPC_620", MACHO_CPU_SUBTYPE_POWERPC_620},
			{"CPU_SUBTYPE_POWERPC_750", MACHO_CPU_SUBTYPE_POWERPC_750},
			{"CPU_SUBTYPE_POWERPC_7400", MACHO_CPU_SUBTYPE_POWERPC_7400},
			{"CPU_SUBTYPE_POWERPC_7450", MACHO_CPU_SUBTYPE_POWERPC_7450},
			{"CPU_SUBTYPE_POWERPC_970", MACHO_CPU_SUBTYPE_POWERPC_970}
			// clang-format on
		});

	auto fileTypeEnum = BuildEnum(view, "file_type_t", 4,
		{
			// clang-format off
			{"MH_OBJECT", MH_OBJECT},
			{"MH_EXECUTE", MH_EXECUTE},
			{"MH_FVMLIB", MH_FVMLIB},
			{"MH_CORE", MH_CORE},
			{"MH_PRELOAD", MH_PRELOAD},
			{"MH_DYLIB", MH_DYLIB},
			{"MH_DYLINKER", MH_DYLINKER},
			{"MH_BUNDLE", MH_BUNDLE},
			{"MH_DYLIB_STUB", MH_DYLIB_STUB},
			{"MH_DSYM", MH_DSYM},
			{"MH_KEXT_BUNDLE", MH_KEXT_BUNDLE},
			{"MH_FILESET", MH_FILESET}
			// clang-format on
		});

	auto flagsTypeEnum = BuildEnum(view, "flags_type_t", 4,
		{
			// clang-format off
			{"MH_NOUNDEFS", MH_NOUNDEFS},
			{"MH_INCRLINK", MH_INCRLINK},
			{"MH_DYLDLINK", MH_DYLDLINK},
			{"MH_BINDATLOAD", MH_BINDATLOAD},
			{"MH_PREBOUND", MH_PREBOUND},
			{"MH_SPLIT_SEGS", MH_SPLIT_SEGS},
			{"MH_LAZY_INIT", MH_LAZY_INIT},
			{"MH_TWOLEVEL", MH_TWOLEVEL},
			{"MH_FORCE_FLAT", MH_FORCE_FLAT},
			{"MH_NOMULTIDEFS", MH_NOMULTIDEFS},
			{"MH_NOFIXPREBINDING", MH_NOFIXPREBINDING},
			{"MH_PREBINDABLE", MH_PREBINDABLE},
			{"MH_ALLMODSBOUND", MH_ALLMODSBOUND},
			{"MH_SUBSECTIONS_VIA_SYMBOLS", MH_SUBSECTIONS_VIA_SYMBOLS},
			{"MH_CANONICAL", MH_CANONICAL},
			{"MH_WEAK_DEFINES", MH_WEAK_DEFINES},
			{"MH_BINDS_TO_WEAK", MH_BINDS_TO_WEAK},
			{"MH_ALLOW_STACK_EXECUTION", MH_ALLOW_STACK_EXECUTION},
			{"MH_ROOT_SAFE", MH_ROOT_SAFE},
			{"MH_SETUID_SAFE", MH_SETUID_SAFE},
			{"MH_NO_REEXPORTED_DYLIBS", MH_NO_REEXPORTED_DYLIBS},
			{"MH_PIE", MH_PIE},
			{"MH_DEAD_STRIPPABLE_DYLIB", MH_DEAD_STRIPPABLE_DYLIB},
			{"MH_HAS_TLV_DESCRIPTORS", MH_HAS_TLV_DESCRIPTORS},
			{"MH_NO_HEAP_EXECUTION", MH_NO_HEAP_EXECUTION},
			{"MH_APP_EXTENSION_SAFE", _MH_APP_EXTENSION_SAFE},
			{"MH_NLIST_OUTOFSYNC_WITH_DYLDINFO", _MH_NLIST_OUTOFSYNC_WITH_DYLDINFO},
			{"MH_SIM_SUPPORT", _MH_SIM_SUPPORT},
			{"MH_DYLIB_IN_CACHE", _MH_DYLIB_IN_CACHE}
			// clang-format on
		});

	Ref<Type> headerType;
	if (view->GetAddressSize() == 8)
	{
		headerType = BuildStruct(view, "mach_header_64", false,
			{
				// clang-format off
				{"magic", Type::IntegerType(4, false)},
				{"cputype", cpuTypeEnum},
				{"cpusubtype", cpuSubTypeEnum},
				{"filetype", fileTypeEnum},
				{"ncmds", Type::IntegerType(4, false)},
				{"sizeofcmds", Type::IntegerType(4, false)},
				{"flags", flagsTypeEnum},
				{"reserved", Type::IntegerType(4, false)}
				// clang-format on
			});
	}
	else
	{
		headerType = BuildStruct(view, "mach_header", false,
			{
				// clang-format off
				{"magic", Type::IntegerType(4, false)},
				{"cputype", cpuTypeEnum},
				{"cpusubtype", cpuSubTypeEnum},
				{"filetype", fileTypeEnum},
				{"ncmds", Type::IntegerType(4, false)},
				{"sizeofcmds", Type::IntegerType(4, false)},
				{"flags", flagsTypeEnum}
				// clang-format on
			});
	}

	auto cmdTypeEnum = BuildEnum(view, "load_command_type_t", 4,
		{
			// clang-format off
			{"LC_REQ_DYLD", LC_REQ_DYLD},
			{"LC_SEGMENT", LC_SEGMENT},
			{"LC_SYMTAB", LC_SYMTAB},
			{"LC_SYMSEG", LC_SYMSEG},
			{"LC_THREAD", LC_THREAD},
			{"LC_UNIXTHREAD", LC_UNIXTHREAD},
			{"LC_LOADFVMLIB", LC_LOADFVMLIB},
			{"LC_IDFVMLIB", LC_IDFVMLIB},
			{"LC_IDENT", LC_IDENT},
			{"LC_FVMFILE", LC_FVMFILE},
			{"LC_PREPAGE", LC_PREPAGE},
			{"LC_DYSYMTAB", LC_DYSYMTAB},
			{"LC_LOAD_DYLIB", LC_LOAD_DYLIB},
			{"LC_ID_DYLIB", LC_ID_DYLIB},
			{"LC_LOAD_DYLINKER", LC_LOAD_DYLINKER},
			{"LC_ID_DYLINKER", LC_ID_DYLINKER},
			{"LC_PREBOUND_DYLIB", LC_PREBOUND_DYLIB},
			{"LC_ROUTINES", LC_ROUTINES},
			{"LC_SUB_FRAMEWORK", LC_SUB_FRAMEWORK},
			{"LC_SUB_UMBRELLA", LC_SUB_UMBRELLA},
			{"LC_SUB_CLIENT", LC_SUB_CLIENT},
			{"LC_SUB_LIBRARY", LC_SUB_LIBRARY},
			{"LC_TWOLEVEL_HINTS", LC_TWOLEVEL_HINTS},
			{"LC_PREBIND_CKSUM", LC_PREBIND_CKSUM},
			{"LC_LOAD_WEAK_DYLIB", LC_LOAD_WEAK_DYLIB},
			{"LC_SEGMENT_64", LC_SEGMENT_64},
			{"LC_ROUTINES_64", LC_ROUTINES_64},
			{"LC_UUID", LC_UUID},
			{"LC_RPATH", LC_RPATH},
			{"LC_CODE_SIGNATURE", LC_CODE_SIGNATURE},
			{"LC_SEGMENT_SPLIT_INFO", LC_SEGMENT_SPLIT_INFO},
			{"LC_REEXPORT_DYLIB", LC_REEXPORT_DYLIB},
			{"LC_LAZY_LOAD_DYLIB", LC_LAZY_LOAD_DYLIB},
			{"LC_ENCRYPTION_INFO", LC_ENCRYPTION_INFO},
			{"LC_DYLD_INFO", LC_DYLD_INFO},
			{"LC_DYLD_INFO_ONLY", LC_DYLD_INFO_ONLY},
			{"LC_LOAD_UPWARD_DYLIB", LC_LOAD_UPWARD_DYLIB},
			{"LC_VERSION_MIN_MACOSX", LC_VERSION_MIN_MACOSX},
			{"LC_VERSION_MIN_IPHONEOS", LC_VERSION_MIN_IPHONEOS},
			{"LC_FUNCTION_STARTS", LC_FUNCTION_STARTS},
			{"LC_DYLD_ENVIRONMENT", LC_DYLD_ENVIRONMENT},
			{"LC_MAIN", LC_MAIN},
			{"LC_DATA_IN_CODE", LC_DATA_IN_CODE},
			{"LC_SOURCE_VERSION", LC_SOURCE_VERSION},
			{"LC_DYLIB_CODE_SIGN_DRS", LC_DYLIB_CODE_SIGN_DRS},
			{"LC_ENCRYPTION_INFO_64", _LC_ENCRYPTION_INFO_64},
			{"LC_LINKER_OPTION", _LC_LINKER_OPTION},
			{"LC_LINKER_OPTIMIZATION_HINT", _LC_LINKER_OPTIMIZATION_HINT},
			{"LC_VERSION_MIN_TVOS", _LC_VERSION_MIN_TVOS},
			{"LC_VERSION_MIN_WATCHOS", LC_VERSION_MIN_WATCHOS},
			{"LC_NOTE", LC_NOTE},
			{"LC_BUILD_VERSION", LC_BUILD_VERSION},
			{"LC_DYLD_EXPORTS_TRIE", LC_DYLD_EXPORTS_TRIE},
			{"LC_DYLD_CHAINED_FIXUPS", LC_DYLD_CHAINED_FIXUPS},
			{"LC_FILESET_ENTRY", LC_FILESET_ENTRY}
			// clang-format on
		});

	auto loadCommandType = BuildStruct(view, "load_command", false,
		{
			// clang-format off
			{"cmd", cmdTypeEnum},
			{"cmdsize", Type::IntegerType(4, false)}
			// clang-format on
		});

	auto protTypeEnum = BuildEnum(view, "vm_prot_t", 4,
		{
			{"VM_PROT_NONE", MACHO_VM_PROT_NONE}, {"VM_PROT_READ", MACHO_VM_PROT_READ},
			{"VM_PROT_WRITE", MACHO_VM_PROT_WRITE}, {"VM_PROT_EXECUTE", MACHO_VM_PROT_EXECUTE},
			// {"VM_PROT_DEFAULT", MACHO_VM_PROT_DEFAULT},
			// {"VM_PROT_ALL", MACHO_VM_PROT_ALL},
			{"VM_PROT_NO_CHANGE", MACHO_VM_PROT_NO_CHANGE}, {"VM_PROT_COPY_OR_WANTS_COPY", MACHO_VM_PROT_COPY}
			// {"VM_PROT_WANTS_COPY", MACHO_VM_PROT_WANTS_COPY},
		});

	auto segFlagsTypeEnum = BuildEnum(view, "sg_flags_t", 4,
		{
			// clang-format off
			{"SG_HIGHVM", SG_HIGHVM},
			{"SG_FVMLIB", SG_FVMLIB},
			{"SG_NORELOC", SG_NORELOC},
			{"SG_PROTECTED_VERSION_1", SG_PROTECTED_VERSION_1}
			// clang-format on
		});

	auto segmentCommandType = BuildStruct(view, "segment_command", false,
		{
			// clang-format off
			{"cmd", cmdTypeEnum},
			{"cmdsize", Type::IntegerType(4, false)},
			{"segname", Type::ArrayType(Type::IntegerType(1, true), 16)},
			{"vmaddr", Type::IntegerType(4, false)},
			{"vmsize", Type::IntegerType(4, false)},
			{"fileoff", Type::IntegerType(4, false)},
			{"filesize", Type::IntegerType(4, false)},
			{"maxprot", protTypeEnum},
			{"initprot", protTypeEnum},
			{"nsects", Type::IntegerType(4, false)},
			{"flags", segFlagsTypeEnum}
			// clang-format on
		});

	auto segmentCommand64Type = BuildStruct(view, "segment_command_64", false,
		{
			// clang-format off
			{"cmd", cmdTypeEnum},
			{"cmdsize", Type::IntegerType(4, false)},
			{"segname", Type::ArrayType(Type::IntegerType(1, true), 16)},
			{"vmaddr", Type::IntegerType(8, false)},
			{"vmsize", Type::IntegerType(8, false)},
			{"fileoff", Type::IntegerType(8, false)},
			{"filesize", Type::IntegerType(8, false)},
			{"maxprot", protTypeEnum},
			{"initprot", protTypeEnum},
			{"nsects", Type::IntegerType(4, false)},
			{"flags", segFlagsTypeEnum}
			// clang-format on
		});

	auto sectionType = BuildStruct(view, "section", true,
		{
			// clang-format off
			{"sectname", Type::ArrayType(Type::IntegerType(1, true), 16)},
			{"segname", Type::ArrayType(Type::IntegerType(1, true), 16)},
			{"addr", Type::IntegerType(4, false)},
			{"size", Type::IntegerType(4, false)},
			{"offset", Type::IntegerType(4, false)},
			{"align", Type::IntegerType(4, false)},
			{"reloff", Type::IntegerType(4, false)},
			{"nreloc", Type::IntegerType(4, false)},
			{"flags", Type::IntegerType(4, false)},
			{"reserved1", Type::IntegerType(4, false)},
			{"reserved2", Type::IntegerType(4, false)}
			// clang-format on
		});

	auto section64Type = BuildStruct(view, "section_64", true,
		{
			// clang-format off
			{"sectname", Type::ArrayType(Type::IntegerType(1, true), 16)},
			{"segname", Type::ArrayType(Type::IntegerType(1, true), 16)},
			{"addr", Type::IntegerType(8, false)},
			{"size", Type::IntegerType(8, false)},
			{"offset", Type::IntegerType(4, false)},
			{"align", Type::IntegerType(4, false)},
			{"reloff", Type::IntegerType(4, false)},
			{"nreloc", Type::IntegerType(4, false)},
			{"flags", Type::IntegerType(4, false)},
			{"reserved1", Type::IntegerType(4, false)},
			{"reserved2", Type::IntegerType(4, false)},
			{"reserved3", Type::IntegerType(4, false)}
			// clang-format on
		});

	auto symtabCommandType = BuildStruct(view, "symtab_command", false,
		{
			// clang-format off
			{"cmd", cmdTypeEnum},
			{"cmdsize", Type::IntegerType(4, false)},
			{"symoff", Type::IntegerType(4, false)},
			{"nsyms", Type::IntegerType(4, false)},
			{"stroff", Type::IntegerType(4, false)},
			{"strsize", Type::IntegerType(4, false)}
			// clang-format on
		});

	auto dysymtabCommandType = BuildStruct(view, "dysymtab_command", false,
		{
			// clang-format off
			{"cmd", cmdTypeEnum},
			{"cmdsize", Type::IntegerType(4, false)},
			{"ilocalsym", Type::IntegerType(4, false)},
			{"nlocalsym", Type::IntegerType(4, false)},
			{"iextdefsym", Type::IntegerType(4, false)},
			{"nextdefsym", Type::IntegerType(4, false)},
			{"iundefsym", Type::IntegerType(4, false)},
			{"nundefsym", Type::IntegerType(4, false)},
			{"tocoff", Type::IntegerType(4, false)},
			{"ntoc", Type::IntegerType(4, false)},
			{"modtaboff", Type::IntegerType(4, false)},
			{"nmodtab", Type::IntegerType(4, false)},
			{"extrefsymoff", Type::IntegerType(4, false)},
			{"nextrefsyms", Type::IntegerType(4, false)},
			{"indirectsymoff", Type::IntegerType(4, false)},
			{"nindirectsyms", Type::IntegerType(4, false)},
			{"extreloff", Type::IntegerType(4, false)},
			{"nextrel", Type::IntegerType(4, false)},
			{"locreloff", Type::IntegerType(4, false)},
			{"nlocrel", Type::IntegerType(4, false)}
			// clang-format on
		});

	auto uuidCommandType = BuildStruct(view, "uuid_command", false,
		{
			// clang-format off
			{"cmd", cmdTypeEnum},
			{"cmdsize", Type::IntegerType(4, false)},
			{"uuid", Type::ArrayType(Type::IntegerType(1, true), 16)}
			// clang-format on
		});

	auto linkeditDataCommandType = BuildStruct(view, "linkedit_data_command", false,
		{
			// clang-format off
			{"cmd", cmdTypeEnum},
			{"cmdsize", Type::IntegerType(4, false)},
			{"dataoff", Type::IntegerType(4, false)},
			{"datasize", Type::IntegerType(4, false)}
			// clang-format on
		});

	auto encryptionInfoCommandType = BuildStruct(view, "encryption_info_command", false,
		{
			// clang-format off
			{"cmd", cmdTypeEnum},
			{"cmdsize", Type::IntegerType(4, false)},
			{"cryptoff", Type::IntegerType(4, false)},
			{"cryptsize", Type::IntegerType(4, false)},
			{"cryptid", Type::IntegerType(4, false)}
			// clang-format on
		});

	auto versionMinCommandType = BuildStruct(view, "version_min_command", false,
		{
			// clang-format off
			{"cmd", cmdTypeEnum},
			{"cmdsize", Type::IntegerType(4, false)},
			{"version", Type::IntegerType(4, false)},
			{"sdk", Type::IntegerType(4, false)}
			// clang-format on
		});

	auto dyldInfoCommandType = BuildStruct(view, "dyld_info_command", false,
		{
			// clang-format off
			{"cmd", cmdTypeEnum},
			{"cmdsize", Type::IntegerType(4, false)},
			{"rebase_off", Type::IntegerType(4, false)},
			{"rebase_size", Type::IntegerType(4, false)},
			{"bind_off", Type::IntegerType(4, false)},
			{"bind_size", Type::IntegerType(4, false)},
			{"weak_bind_off", Type::IntegerType(4, false)},
			{"weak_bind_size", Type::IntegerType(4, false)},
			{"lazy_bind_off", Type::IntegerType(4, false)},
			{"lazy_bind_size", Type::IntegerType(4, false)},
			{"export_off", Type::IntegerType(4, false)},
			{"export_size", Type::IntegerType(4, false)}
			// clang-format on
		});

	auto dylibType = BuildStruct(view, "dylib", false,
		{
			// clang-format off
			{"name", Type::IntegerType(4, false)},
			{"timestamp", Type::IntegerType(4, false)},
			{"current_version", Type::IntegerType(4, false)},
			{"compatibility_version", Type::IntegerType(4, false)}
			// clang-format on
		});

	auto dylibCommandType = BuildStruct(view, "dylib_command", false,
		{
			// clang-format off
			{"cmd", cmdTypeEnum},
			{"cmdsize", Type::IntegerType(4, false)},
			{"dylib", dylibType}
			// clang-format on
		});

	auto filesetEntryCommandType = BuildStruct(view, "fileset_entry_command", false,
		{
			// clang-format off
			{"cmd", cmdTypeEnum},
			{"cmdsize", Type::IntegerType(4, false)},
			{"vmaddr", Type::IntegerType(8, false)},
			{"fileoff", Type::IntegerType(8, false)},
			{"entry_id", Type::IntegerType(4, false)},
			{"reserved", Type::IntegerType(4, false)}
			// clang-format on
		});

	auto unixThreadCommandType = BuildStruct(view, "unix_thread_command", false,
		{
			// clang-format off
			{"cmd", cmdTypeEnum},
			{"cmdsize", Type::IntegerType(4, false)},
			{"flavor", Type::IntegerType(4, false)},
			{"count", Type::IntegerType(4, false)},
			// The 'state' field is intentionally ignored.
			// clang-format off
		});
}

void ApplyHeaderTypes(Ref<BinaryView> view, Ref<Logger> logger, const BinaryReader& incomingReader,
	std::string_view imageName, uint64_t headerAddress, size_t loadCommandCount)
{
	BinaryReader reader(view, incomingReader.GetEndianness());
	std::string symbolSuffix = imageName.empty() ? "" : fmt::format("::{}", imageName);

	auto headerType =
		Type::NamedType(view, QualifiedName(view->GetAddressSize() == 8 ? "mach_header_64" : "mach_header"));
	reader.Seek(headerAddress + headerType->GetWidth());

	view->DefineDataVariable(headerAddress, headerType);
	view->DefineAutoSymbol(
		new Symbol(DataSymbol, fmt::format("__macho_header{}", symbolSuffix), headerAddress, LocalBinding));

	auto applyLoadCommand = [&](uint64_t cmdAddr, const load_command& load) {
		switch (load.cmd)
		{
		case LC_SEGMENT:
		{
			view->DefineDataVariable(cmdAddr, Type::NamedType(view, QualifiedName("segment_command")));
			reader.SeekRelative(5 * 8);
			size_t numSections = reader.Read32();
			reader.SeekRelative(4);
			for (size_t j = 0; j < numSections; j++)
			{
				view->DefineDataVariable(reader.GetOffset(), Type::NamedType(view, QualifiedName("section")));
				auto sectionSymName = fmt::format("__macho_section{}_[{}]", symbolSuffix, j);
				auto sectionSym = new Symbol(DataSymbol, sectionSymName, reader.GetOffset(), LocalBinding);
				view->DefineAutoSymbol(sectionSym);
				reader.SeekRelative((8 * 8) + 4);
			}
			break;
		}
		case LC_SEGMENT_64:
		{
			view->DefineDataVariable(cmdAddr, Type::NamedType(view, QualifiedName("segment_command_64")));
			reader.SeekRelative(7 * 8);
			size_t numSections = reader.Read32();
			reader.SeekRelative(4);
			for (size_t j = 0; j < numSections; j++)
			{
				view->DefineDataVariable(reader.GetOffset(), Type::NamedType(view, QualifiedName("section_64")));
				auto sectionSymName = fmt::format("__macho_section_64{}_[{}]", symbolSuffix, j);
				auto sectionSym = new Symbol(DataSymbol, sectionSymName, reader.GetOffset(), LocalBinding);
				view->DefineAutoSymbol(sectionSym);
				reader.SeekRelative(10 * 8);
			}
			break;
		}
		case LC_SYMTAB:
			view->DefineDataVariable(cmdAddr, Type::NamedType(view, QualifiedName("symtab_command")));
			break;
		case LC_DYSYMTAB:
			view->DefineDataVariable(cmdAddr, Type::NamedType(view, QualifiedName("dysymtab_command")));
			break;
		case LC_UUID:
			view->DefineDataVariable(cmdAddr, Type::NamedType(view, QualifiedName("uuid_command")));
			break;
		case LC_ID_DYLIB:
		case LC_LOAD_DYLIB:
		case LC_REEXPORT_DYLIB:
		case LC_LOAD_WEAK_DYLIB:
		case LC_LOAD_UPWARD_DYLIB:
			view->DefineDataVariable(cmdAddr, Type::NamedType(view, QualifiedName("dylib_command")));
			if (load.cmdsize - 24 <= 150)
				view->DefineDataVariable(
					cmdAddr + 24, Type::ArrayType(Type::IntegerType(1, true), load.cmdsize - 24));
			break;
		case LC_CODE_SIGNATURE:
		case LC_SEGMENT_SPLIT_INFO:
		case LC_FUNCTION_STARTS:
		case LC_DATA_IN_CODE:
		case LC_DYLIB_CODE_SIGN_DRS:
		case LC_DYLD_EXPORTS_TRIE:
		case LC_DYLD_CHAINED_FIXUPS:
			view->DefineDataVariable(cmdAddr, Type::NamedType(view, QualifiedName("linkedit_data_command")));
			break;
		case LC_ENCRYPTION_INFO:
			view->DefineDataVariable(cmdAddr, Type::NamedType(view, QualifiedName("encryption_info_command")));
			break;
		case LC_VERSION_MIN_MACOSX:
		case LC_VERSION_MIN_IPHONEOS:
			view->DefineDataVariable(cmdAddr, Type::NamedType(view, QualifiedName("version_min_command")));
			break;
		case LC_DYLD_INFO:
		case LC_DYLD_INFO_ONLY:
			view->DefineDataVariable(cmdAddr, Type::NamedType(view, QualifiedName("dyld_info_command")));
			break;
		case LC_FILESET_ENTRY:
			view->DefineDataVariable(cmdAddr, Type::NamedType(view, QualifiedName("fileset_entry_command")));
			break;
		case LC_UNIXTHREAD:
		{
			view->DefineDataVariable(cmdAddr, Type::NamedType(view, QualifiedName("unix_thread_command")));
			reader.SeekRelative(4);
			uint32_t count = reader.Read32();
			view->DefineDataVariable(reader.GetOffset(), Type::ArrayType(Type::IntegerType(8, true), count));
			break;
		}
		default:
			view->DefineDataVariable(cmdAddr, Type::NamedType(view, QualifiedName("load_command")));
			break;
		}
	};

	try
	{
		for (size_t i = 0; i < loadCommandCount; i++)
		{
			load_command load {};
			uint64_t curOffset = reader.GetOffset();
			load.cmd = reader.Read32();
			load.cmdsize = reader.Read32();

			applyLoadCommand(curOffset, load);
			view->DefineAutoSymbol(new Symbol(
				DataSymbol, fmt::format("__macho_load_command{}_[{}]", symbolSuffix, i), curOffset, LocalBinding));

			uint64_t nextOffset = curOffset + load.cmdsize;
			reader.Seek(nextOffset);
		}
	}
	catch (ReadException&)
	{
		if (logger)
			logger->LogError("Error when applying Mach-O header types at %llx", headerAddress);
		else
			LogError("Error when applying Mach-O header types at %llx", headerAddress);
	}
}

}  // namespace BinaryNinja::MachO
