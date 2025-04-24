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

	StructureBuilder machoHeaderBuilder;
	machoHeaderBuilder.AddMember(Type::IntegerType(4, false), "magic");
	machoHeaderBuilder.AddMember(cpuTypeEnum, "cputype");
	machoHeaderBuilder.AddMember(cpuSubTypeEnum, "cpusubtype");
	machoHeaderBuilder.AddMember(fileTypeEnum, "filetype");
	machoHeaderBuilder.AddMember(Type::IntegerType(4, false), "ncmds");
	machoHeaderBuilder.AddMember(Type::IntegerType(4, false), "sizeofcmds");
	machoHeaderBuilder.AddMember(flagsTypeEnum, "flags");
	if (view->GetAddressSize() == 8)
		machoHeaderBuilder.AddMember(Type::IntegerType(4, false), "reserved");
	Ref<Structure> machoHeaderStruct = machoHeaderBuilder.Finalize();
	QualifiedName headerName(view->GetAddressSize() == 8 ? "mach_header_64" : "mach_header");

	std::string headerTypeId = Type::GenerateAutoTypeId("macho", headerName);
	Ref<Type> machoHeaderType = Type::StructureType(machoHeaderStruct);
	auto headerQualName = view->DefineType(headerTypeId, headerName, machoHeaderType);

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

	StructureBuilder loadCommandBuilder;
	loadCommandBuilder.AddMember(cmdTypeEnum, "cmd");
	loadCommandBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	Ref<Structure> loadCommandStruct = loadCommandBuilder.Finalize();
	QualifiedName loadCommandName("load_command");
	std::string loadCommandTypeId = Type::GenerateAutoTypeId("macho", loadCommandName);
	Ref<Type> loadCommandType = Type::StructureType(loadCommandStruct);
	auto loadCommandQualName = view->DefineType(loadCommandTypeId, loadCommandName, loadCommandType);

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

	StructureBuilder loadSegmentCommandBuilder;
	loadSegmentCommandBuilder.AddMember(cmdTypeEnum, "cmd");
	loadSegmentCommandBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	loadSegmentCommandBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 16), "segname");
	loadSegmentCommandBuilder.AddMember(Type::IntegerType(4, false), "vmaddr");
	loadSegmentCommandBuilder.AddMember(Type::IntegerType(4, false), "vmsize");
	loadSegmentCommandBuilder.AddMember(Type::IntegerType(4, false), "fileoff");
	loadSegmentCommandBuilder.AddMember(Type::IntegerType(4, false), "filesize");
	loadSegmentCommandBuilder.AddMember(protTypeEnum, "maxprot");
	loadSegmentCommandBuilder.AddMember(protTypeEnum, "initprot");
	loadSegmentCommandBuilder.AddMember(Type::IntegerType(4, false), "nsects");
	loadSegmentCommandBuilder.AddMember(segFlagsTypeEnum, "flags");
	Ref<Structure> loadSegmentCommandStruct = loadSegmentCommandBuilder.Finalize();
	QualifiedName loadSegmentCommandName("segment_command");
	std::string loadSegmentCommandTypeId = Type::GenerateAutoTypeId("macho", loadSegmentCommandName);
	Ref<Type> loadSegmentCommandType = Type::StructureType(loadSegmentCommandStruct);
	auto loadSegmentCommandQualName =
		view->DefineType(loadSegmentCommandTypeId, loadSegmentCommandName, loadSegmentCommandType);

	StructureBuilder loadSegmentCommand64Builder;
	loadSegmentCommand64Builder.AddMember(cmdTypeEnum, "cmd");
	loadSegmentCommand64Builder.AddMember(Type::IntegerType(4, false), "cmdsize");
	loadSegmentCommand64Builder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 16), "segname");
	loadSegmentCommand64Builder.AddMember(Type::IntegerType(8, false), "vmaddr");
	loadSegmentCommand64Builder.AddMember(Type::IntegerType(8, false), "vmsize");
	loadSegmentCommand64Builder.AddMember(Type::IntegerType(8, false), "fileoff");
	loadSegmentCommand64Builder.AddMember(Type::IntegerType(8, false), "filesize");
	loadSegmentCommand64Builder.AddMember(protTypeEnum, "maxprot");
	loadSegmentCommand64Builder.AddMember(protTypeEnum, "initprot");
	loadSegmentCommand64Builder.AddMember(Type::IntegerType(4, false), "nsects");
	loadSegmentCommand64Builder.AddMember(segFlagsTypeEnum, "flags");
	Ref<Structure> loadSegmentCommand64Struct = loadSegmentCommand64Builder.Finalize();
	QualifiedName loadSegment64CommandName("segment_command_64");
	std::string loadSegment64CommandTypeId = Type::GenerateAutoTypeId("macho", loadSegment64CommandName);
	Ref<Type> loadSegment64CommandType = Type::StructureType(loadSegmentCommand64Struct);
	auto loadSegment64CommandQualName =
		view->DefineType(loadSegment64CommandTypeId, loadSegment64CommandName, loadSegment64CommandType);

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
	QualifiedName sectionName("section");
	std::string sectionTypeId = Type::GenerateAutoTypeId("macho", sectionName);
	Ref<Type> sectionType = Type::StructureType(sectionStruct);
	auto sectionQualName = view->DefineType(sectionTypeId, sectionName, sectionType);

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
	QualifiedName section64Name("section_64");
	std::string section64TypeId = Type::GenerateAutoTypeId("macho", section64Name);
	Ref<Type> section64Type = Type::StructureType(section64Struct);
	auto section64QualName = view->DefineType(section64TypeId, section64Name, section64Type);

	StructureBuilder symtabBuilder;
	symtabBuilder.AddMember(cmdTypeEnum, "cmd");
	symtabBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	symtabBuilder.AddMember(Type::IntegerType(4, false), "symoff");
	symtabBuilder.AddMember(Type::IntegerType(4, false), "nsyms");
	symtabBuilder.AddMember(Type::IntegerType(4, false), "stroff");
	symtabBuilder.AddMember(Type::IntegerType(4, false), "strsize");
	Ref<Structure> symtabStruct = symtabBuilder.Finalize();
	QualifiedName symtabName("symtab");
	std::string symtabTypeId = Type::GenerateAutoTypeId("macho", symtabName);
	Ref<Type> symtabType = Type::StructureType(symtabStruct);
	auto symtabQualName = view->DefineType(symtabTypeId, symtabName, symtabType);

	StructureBuilder dynsymtabBuilder;
	dynsymtabBuilder.AddMember(cmdTypeEnum, "cmd");
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
	QualifiedName dynsymtabName("dysymtab");
	std::string dynsymtabTypeId = Type::GenerateAutoTypeId("macho", dynsymtabName);
	Ref<Type> dynsymtabType = Type::StructureType(dynsymtabStruct);
	auto dynsymtabQualName = view->DefineType(dynsymtabTypeId, dynsymtabName, dynsymtabType);

	StructureBuilder uuidBuilder;
	uuidBuilder.AddMember(cmdTypeEnum, "cmd");
	uuidBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	uuidBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, false), 16), "uuid");
	Ref<Structure> uuidStruct = uuidBuilder.Finalize();
	QualifiedName uuidName("uuid");
	std::string uuidTypeId = Type::GenerateAutoTypeId("macho", uuidName);
	Ref<Type> uuidType = Type::StructureType(uuidStruct);
	auto uuidQualName = view->DefineType(uuidTypeId, uuidName, uuidType);

	StructureBuilder linkeditDataBuilder;
	linkeditDataBuilder.AddMember(cmdTypeEnum, "cmd");
	linkeditDataBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	linkeditDataBuilder.AddMember(Type::IntegerType(4, false), "dataoff");
	linkeditDataBuilder.AddMember(Type::IntegerType(4, false), "datasize");
	Ref<Structure> linkeditDataStruct = linkeditDataBuilder.Finalize();
	QualifiedName linkeditDataName("linkedit_data");
	std::string linkeditDataTypeId = Type::GenerateAutoTypeId("macho", linkeditDataName);
	Ref<Type> linkeditDataType = Type::StructureType(linkeditDataStruct);
	auto linkeditDataQualName = view->DefineType(linkeditDataTypeId, linkeditDataName, linkeditDataType);

	StructureBuilder encryptionInfoBuilder;
	encryptionInfoBuilder.AddMember(cmdTypeEnum, "cmd");
	encryptionInfoBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	encryptionInfoBuilder.AddMember(Type::IntegerType(4, false), "cryptoff");
	encryptionInfoBuilder.AddMember(Type::IntegerType(4, false), "cryptsize");
	encryptionInfoBuilder.AddMember(Type::IntegerType(4, false), "cryptid");
	Ref<Structure> encryptionInfoStruct = encryptionInfoBuilder.Finalize();
	QualifiedName encryptionInfoName("encryption_info");
	std::string encryptionInfoTypeId = Type::GenerateAutoTypeId("macho", encryptionInfoName);
	Ref<Type> encryptionInfoType = Type::StructureType(encryptionInfoStruct);
	auto encryptionInfoQualName = view->DefineType(encryptionInfoTypeId, encryptionInfoName, encryptionInfoType);

	StructureBuilder versionMinBuilder;
	versionMinBuilder.AddMember(cmdTypeEnum, "cmd");
	versionMinBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	versionMinBuilder.AddMember(Type::IntegerType(4, false), "version");
	versionMinBuilder.AddMember(Type::IntegerType(4, false), "sdk");
	Ref<Structure> versionMinStruct = versionMinBuilder.Finalize();
	QualifiedName versionMinName("version_min");
	std::string versionMinTypeId = Type::GenerateAutoTypeId("macho", versionMinName);
	Ref<Type> versionMinType = Type::StructureType(versionMinStruct);
	auto versionMinQualName = view->DefineType(versionMinTypeId, versionMinName, versionMinType);

	StructureBuilder dyldInfoBuilder;
	dyldInfoBuilder.AddMember(cmdTypeEnum, "cmd");
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
	QualifiedName dyldInfoName("dyld_info");
	std::string dyldInfoTypeId = Type::GenerateAutoTypeId("macho", dyldInfoName);
	Ref<Type> dyldInfoType = Type::StructureType(dyldInfoStruct);
	auto dyldInfoQualName = view->DefineType(dyldInfoTypeId, dyldInfoName, dyldInfoType);

	StructureBuilder dylibBuilder;
	dylibBuilder.AddMember(Type::IntegerType(4, false), "name");
	dylibBuilder.AddMember(Type::IntegerType(4, false), "timestamp");
	dylibBuilder.AddMember(Type::IntegerType(4, false), "current_version");
	dylibBuilder.AddMember(Type::IntegerType(4, false), "compatibility_version");
	Ref<Structure> dylibStruct = dylibBuilder.Finalize();
	QualifiedName dylibName("dylib");
	std::string dylibTypeId = Type::GenerateAutoTypeId("macho", dylibName);
	Ref<Type> dylibType = Type::StructureType(dylibStruct);
	auto dylibQualName = view->DefineType(dylibTypeId, dylibName, dylibType);

	StructureBuilder dylibCommandBuilder;
	dylibCommandBuilder.AddMember(cmdTypeEnum, "cmd");
	dylibCommandBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	dylibCommandBuilder.AddMember(Type::NamedType(view, dylibQualName), "dylib");
	Ref<Structure> dylibCommandStruct = dylibCommandBuilder.Finalize();
	QualifiedName dylibCommandName("dylib_command");
	std::string dylibCommandTypeId = Type::GenerateAutoTypeId("macho", dylibCommandName);
	Ref<Type> dylibCommandType = Type::StructureType(dylibCommandStruct);
	auto dylibCommandQualName = view->DefineType(dylibCommandTypeId, dylibCommandName, dylibCommandType);

	StructureBuilder filesetEntryCommandBuilder;
	filesetEntryCommandBuilder.AddMember(cmdTypeEnum, "cmd");
	filesetEntryCommandBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	filesetEntryCommandBuilder.AddMember(Type::IntegerType(8, false), "vmaddr");
	filesetEntryCommandBuilder.AddMember(Type::IntegerType(8, false), "fileoff");
	filesetEntryCommandBuilder.AddMember(Type::IntegerType(4, false), "entry_id");
	filesetEntryCommandBuilder.AddMember(Type::IntegerType(4, false), "reserved");
	Ref<Structure> filesetEntryCommandStruct = filesetEntryCommandBuilder.Finalize();
	QualifiedName filesetEntryCommandName("fileset_entry_command");
	std::string filesetEntryCommandTypeId = Type::GenerateAutoTypeId("macho", filesetEntryCommandName);
	Ref<Type> filesetEntryCommandType = Type::StructureType(filesetEntryCommandStruct);
	auto filesetEntryCommandQualName =
		view->DefineType(filesetEntryCommandTypeId, filesetEntryCommandName, filesetEntryCommandType);

	StructureBuilder unixThreadCommandBuilder;
	unixThreadCommandBuilder.AddMember(cmdTypeEnum, "cmd");
	unixThreadCommandBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	unixThreadCommandBuilder.AddMember(Type::IntegerType(4, false), "flavor");
	unixThreadCommandBuilder.AddMember(Type::IntegerType(4, false), "count");
	// The 'state' field is intentionally ignored.
	Ref<Structure> unixThreadCommandStruct = unixThreadCommandBuilder.Finalize();
	QualifiedName unixThreadCommandName = std::string("unix_thread_command");
	std::string unixThreadCommandTypeId = Type::GenerateAutoTypeId("macho", unixThreadCommandName);
	Ref<Type> unixThreadCommandType = Type::StructureType(unixThreadCommandStruct);
	auto unixThreadCommandQualName =
		view->DefineType(unixThreadCommandTypeId, unixThreadCommandName, unixThreadCommandType);
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
			view->DefineDataVariable(cmdAddr, Type::NamedType(view, QualifiedName("symtab")));
			break;
		case LC_DYSYMTAB:
			view->DefineDataVariable(cmdAddr, Type::NamedType(view, QualifiedName("dysymtab")));
			break;
		case LC_UUID:
			view->DefineDataVariable(cmdAddr, Type::NamedType(view, QualifiedName("uuid")));
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
			view->DefineDataVariable(cmdAddr, Type::NamedType(view, QualifiedName("linkedit_data")));
			break;
		case LC_ENCRYPTION_INFO:
			view->DefineDataVariable(cmdAddr, Type::NamedType(view, QualifiedName("encryption_info")));
			break;
		case LC_VERSION_MIN_MACOSX:
		case LC_VERSION_MIN_IPHONEOS:
			view->DefineDataVariable(cmdAddr, Type::NamedType(view, QualifiedName("version_min")));
			break;
		case LC_DYLD_INFO:
		case LC_DYLD_INFO_ONLY:
			view->DefineDataVariable(cmdAddr, Type::NamedType(view, QualifiedName("dyld_info")));
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
