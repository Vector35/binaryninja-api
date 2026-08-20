#include "KernelCacheView.h"
#include <regex>
#include <filesystem>
#include <MachOProcessor.h>

#include "KernelCacheController.h"
#include "KernelCacheBuilder.h"

using namespace BinaryNinja;
using namespace BinaryNinja::KC;

static KernelCacheViewType* g_kcViewType;

KernelCacheViewType::KernelCacheViewType() : BinaryViewType(KC_VIEW_NAME, KC_VIEW_NAME) {}

// We register all our one-shot stuff here, such as the object destructor.
void KernelCacheViewType::Register()
{
	RegisterKernelCacheControllerDestructor();

	static KernelCacheViewType kcViewType;
	BinaryViewType::Register(&kcViewType);

	g_kcViewType = &kcViewType;
}

Ref<BinaryView> KernelCacheViewType::Create(BinaryView* data)
{
	try
	{
		return new KernelCacheView(KC_VIEW_NAME, data, false);
	}
	catch (std::exception& e)
	{
		LogErrorForException(e, "%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}

Ref<Settings> KernelCacheViewType::GetLoadSettingsForData(BinaryView* data)
{
	Ref<BinaryView> viewRef = Parse(data);
	if (!viewRef || !viewRef->Init())
	{
		LogWarnF("Failed to initialize view of type {:?}. Generating default load settings.", GetName());
		viewRef = data;
	}

	Ref<Settings> settings = GetDefaultLoadSettingsForData(viewRef);

	// specify default load settings that can be overridden
	std::vector<std::string> overrides = {"loader.imageBase", "loader.platform"};
	settings->UpdateProperty("loader.imageBase", "message", "Note: File indicates image is not relocatable.");

	for (const auto& override : overrides)
	{
		if (settings->Contains(override))
			settings->UpdateProperty(override, "readOnly", false);
	}

	settings->RegisterSetting("loader.kc.autoLoadPattern",
		R"({
		"title" : "Image Auto-Load Regex Pattern",
		"type" : "string",
		"default" : "",
		"description" : "A regex pattern to auto load matching images at the end of view init, defaults to the system_c image only."
		})");

	settings->RegisterSetting("loader.kc.processFunctionStarts",
		R"({
			"title" : "Process Mach-O Function Starts Tables",
			"type" : "boolean",
			"default" : true,
			"description" : "Add function starts sourced from the Function Starts tables to the core for analysis."
			})");

	// Place the synthetic sections well after the kernel cache to ensure they do
	// not collide with any images that are later loaded from the kernel cache.
	constexpr uint64_t syntheticSectionsOffset = 256 * 1024 * 1024;
	settings->UpdateProperty("loader.syntheticSectionBase", "default", viewRef->GetStart() + syntheticSectionsOffset);

	// Merge existing load settings if they exist. This allows for the selection of a specific object file from a Mach-O
	// Universal file. The 'Universal' BinaryViewType generates a schema with 'loader.universal.architectures'. This
	// schema contains an appropriate 'Mach-O' load schema for selecting a specific object file. The embedded schema
	// contains 'loader.macho.universalImageOffset'.
	Ref<Settings> loadSettings = viewRef->GetLoadSettings(GetName());
	if (loadSettings && !loadSettings->IsEmpty())
		settings->DeserializeSchema(loadSettings->SerializeSchema());

	return settings;
}

Ref<BinaryView> KernelCacheViewType::Parse(BinaryView* data)
{
	try
	{
		return new KernelCacheView(KC_VIEW_NAME, data, true);
	}
	catch (std::exception& e)
	{
		LogErrorForException(e, "%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}

bool KernelCacheViewType::IsTypeValidForData(BinaryView* data)
{
	if (!data)
		return false;

	uint32_t magic;
	data->Read(&magic, data->GetStart(), 4);

	// TODO determine if the "krnl" string of the IMG4 container is required for non-database files
	// If so, inspect the metadata from the TransformSession that produced this BinaryView
	if (magic != MH_CIGAM_64 && magic != MH_MAGIC_64)
		return false;

	uint32_t fileType;
	data->Read(&fileType, data->GetStart() + 0xc, 4);
	if (fileType != MH_FILESET)
		return false;

	return true;
}

KernelCacheView::KernelCacheView(const std::string& typeName, BinaryView* data, bool parseOnly) :
	BinaryView(typeName, data->GetFile(), data), m_parseOnly(parseOnly)
{
}

bool KernelCacheView::Init()
{
	m_logger = new Logger("KernelCache.View", GetFile()->GetSessionId());

	BinaryReader reader(GetParentView());
	reader.Seek(0x4);
	uint32_t cpuType = reader.Read32();
	reader.Seek(0x10);
	uint64_t ncmds = reader.Read32();
	uint64_t sizeofcmds = reader.Read32();

	// get __TEXT seg offset
	uint64_t textSegOffset = 0;
	uint64_t anyFilesetHeaderFileOffset = 0;
	uint64_t offset = 0x20;
	for (uint64_t i = 0; i < ncmds; i++)
	{
		reader.Seek(offset);
		uint64_t cmd = reader.Read32();
		uint64_t cmdsize = reader.Read32();
		if (textSegOffset == 0 && cmd == LC_SEGMENT_64)
		{
			uint64_t segname = reader.Read64();
			reader.Read64();
			uint64_t vmaddr = reader.Read64();
			if (segname == 0x545845545f5f) // __TEXT
			{
				textSegOffset = vmaddr;
			}
		}

		if (anyFilesetHeaderFileOffset == 0 && cmd == LC_FILESET_ENTRY)
		{
			reader.SeekRelative(8);
			anyFilesetHeaderFileOffset = reader.Read64();
		}

		offset += cmdsize;
		if (textSegOffset && anyFilesetHeaderFileOffset)
			break;
	}

	Ref<Platform> platform;
	Ref<Architecture> architecture;

	if (anyFilesetHeaderFileOffset)
	{
		reader.Seek(anyFilesetHeaderFileOffset);
		reader.SeekRelative(0x10);

		uint64_t ncmdsFH = reader.Read32();

		reader.Seek(anyFilesetHeaderFileOffset + 0x20);
		offset = anyFilesetHeaderFileOffset + 0x20;
		bool foundBuildVersion = false;
		for (uint64_t i = 0; i < ncmdsFH; i++)
		{
			reader.Seek(offset);
			uint64_t cmd = reader.Read32();
			uint64_t cmdsize = reader.Read32();
			if (cmd == LC_BUILD_VERSION)
			{
				uint32_t platformID = reader.Read32();
				std::map<std::string, Ref<Metadata>> metadataMap = {
					{"machoplatform", new Metadata((uint64_t) platformID)},
				};
				Ref<Metadata> metadata = new Metadata(metadataMap);
				Ref<Platform> plat = g_kcViewType->RecognizePlatform(cpuType, GetDefaultEndianness(), this, metadata);
				SetDefaultArchitecture(plat->GetArchitecture());
				SetDefaultPlatform(plat);
				foundBuildVersion = true;
			}
			offset += cmdsize;
		}
		if (!foundBuildVersion)
		{
			// FIXME: Is it in-spec to have LC_BUILD_VERSION only in the super header?
			// This is sufficient as a fallback but source should be referenced here.
			LogWarn("Failed to find LC_BUILD_VERSION in subheader. Assuming macOS platform.");
			std::map<std::string, Ref<Metadata>> metadataMap = {
				{"machoplatform", new Metadata((uint64_t) MACHO_PLATFORM_MACOS)},
			};
			Ref<Metadata> metadata = new Metadata(metadataMap);
			Ref<Platform> plat = g_kcViewType->RecognizePlatform(cpuType, GetDefaultEndianness(), this, metadata);
			SetDefaultArchitecture(plat->GetArchitecture());
			SetDefaultPlatform(plat);
		}
	}
	else
	{
		LogError("MH_FILESET had no subheaders");
		return false;
	}

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
	std::string cpuTypeEnumName = "cpu_type_t";
	std::string cpuTypeEnumId = Type::GenerateAutoTypeId("macho", cpuTypeEnumName);
	DefineType(cpuTypeEnumId, cpuTypeEnumName, cpuTypeEnumType);

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
	std::string fileTypeEnumName = "file_type_t";
	std::string fileTypeEnumId = Type::GenerateAutoTypeId("macho", fileTypeEnumName);
	DefineType(fileTypeEnumId, fileTypeEnumName, fileTypeEnumType);

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
	std::string flagsTypeEnumName = "flags_type_t";
	std::string flagsTypeEnumId = Type::GenerateAutoTypeId("macho", flagsTypeEnumName);
	DefineType(flagsTypeEnumId, flagsTypeEnumName, flagsTypeEnumType);

	StructureBuilder machoHeaderBuilder;
	machoHeaderBuilder.AddMember(Type::IntegerType(4, false), "magic");
	machoHeaderBuilder.AddMember(Type::NamedType(this, QualifiedName("cpu_type_t")), "cputype");
	machoHeaderBuilder.AddMember(Type::IntegerType(4, false), "cpusubtype");
	machoHeaderBuilder.AddMember(Type::NamedType(this, QualifiedName("file_type_t")), "filetype");
	machoHeaderBuilder.AddMember(Type::IntegerType(4, false), "ncmds");
	machoHeaderBuilder.AddMember(Type::IntegerType(4, false), "sizeofcmds");
	machoHeaderBuilder.AddMember(Type::NamedType(this, QualifiedName("flags_type_t")), "flags");
	if (GetAddressSize() == 8)
		machoHeaderBuilder.AddMember(Type::IntegerType(4, false), "reserved");
	Ref<Structure> machoHeaderStruct = machoHeaderBuilder.Finalize();
	QualifiedName headerName = (GetAddressSize() == 8) ? std::string("mach_header_64") : std::string("mach_header");

	std::string headerTypeId = Type::GenerateAutoTypeId("macho", headerName);
	Ref<Type> machoHeaderType = Type::StructureType(machoHeaderStruct);
	DefineType(headerTypeId, headerName, machoHeaderType);

	EnumerationBuilder cmdTypeBuilder;
	cmdTypeBuilder.AddMemberWithValue("LC_REQ_DYLD", LC_REQ_DYLD);
	cmdTypeBuilder.AddMemberWithValue("LC_SEGMENT", LC_SEGMENT);
	cmdTypeBuilder.AddMemberWithValue("LC_SYMTAB", LC_SYMTAB);
	cmdTypeBuilder.AddMemberWithValue("LC_SYMSEG", LC_SYMSEG);
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
	cmdTypeBuilder.AddMemberWithValue("LC_LOAD_WEAK_DYLIB", LC_LOAD_WEAK_DYLIB);  //       (0x18 | LC_REQ_DYLD)
	cmdTypeBuilder.AddMemberWithValue("LC_SEGMENT_64", LC_SEGMENT_64);
	cmdTypeBuilder.AddMemberWithValue("LC_ROUTINES_64", LC_ROUTINES_64);
	cmdTypeBuilder.AddMemberWithValue("LC_UUID", LC_UUID);
	cmdTypeBuilder.AddMemberWithValue("LC_RPATH", LC_RPATH);  //                 (0x1c | LC_REQ_DYLD)
	cmdTypeBuilder.AddMemberWithValue("LC_CODE_SIGNATURE", LC_CODE_SIGNATURE);
	cmdTypeBuilder.AddMemberWithValue("LC_SEGMENT_SPLIT_INFO", LC_SEGMENT_SPLIT_INFO);
	cmdTypeBuilder.AddMemberWithValue("LC_REEXPORT_DYLIB", LC_REEXPORT_DYLIB);	//        (0x1f | LC_REQ_DYLD)
	cmdTypeBuilder.AddMemberWithValue("LC_LAZY_LOAD_DYLIB", LC_LAZY_LOAD_DYLIB);
	cmdTypeBuilder.AddMemberWithValue("LC_ENCRYPTION_INFO", LC_ENCRYPTION_INFO);
	cmdTypeBuilder.AddMemberWithValue("LC_DYLD_INFO", LC_DYLD_INFO);
	cmdTypeBuilder.AddMemberWithValue("LC_DYLD_INFO_ONLY", LC_DYLD_INFO_ONLY);		  //        (0x22 | LC_REQ_DYLD)
	cmdTypeBuilder.AddMemberWithValue("LC_LOAD_UPWARD_DYLIB", LC_LOAD_UPWARD_DYLIB);  //     (0x23 | LC_REQ_DYLD)
	cmdTypeBuilder.AddMemberWithValue("LC_VERSION_MIN_MACOSX", LC_VERSION_MIN_MACOSX);
	cmdTypeBuilder.AddMemberWithValue("LC_VERSION_MIN_IPHONEOS", LC_VERSION_MIN_IPHONEOS);
	cmdTypeBuilder.AddMemberWithValue("LC_FUNCTION_STARTS", LC_FUNCTION_STARTS);
	cmdTypeBuilder.AddMemberWithValue("LC_DYLD_ENVIRONMENT", LC_DYLD_ENVIRONMENT);
	cmdTypeBuilder.AddMemberWithValue("LC_MAIN", LC_MAIN);	//                  (0x28 | LC_REQ_DYLD)
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
	std::string cmdTypeEnumName = "load_command_type_t";
	std::string cmdTypeEnumId = Type::GenerateAutoTypeId("macho", cmdTypeEnumName);
	DefineType(cmdTypeEnumId, cmdTypeEnumName, cmdTypeEnumType);

	StructureBuilder loadCommandBuilder;
	loadCommandBuilder.AddMember(Type::NamedType(this, QualifiedName("load_command_type_t")), "cmd");
	loadCommandBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	Ref<Structure> loadCommandStruct = loadCommandBuilder.Finalize();
	QualifiedName loadCommandName = std::string("load_command");
	std::string loadCommandTypeId = Type::GenerateAutoTypeId("macho", loadCommandName);
	Ref<Type> loadCommandType = Type::StructureType(loadCommandStruct);
	DefineType(loadCommandTypeId, loadCommandName, loadCommandType);

	EnumerationBuilder protTypeBuilder;
	protTypeBuilder.AddMemberWithValue("VM_PROT_NONE", MACHO_VM_PROT_NONE);
	protTypeBuilder.AddMemberWithValue("VM_PROT_READ", MACHO_VM_PROT_READ);
	protTypeBuilder.AddMemberWithValue("VM_PROT_WRITE", MACHO_VM_PROT_WRITE);
	protTypeBuilder.AddMemberWithValue("VM_PROT_EXECUTE", MACHO_VM_PROT_EXECUTE);
	// protTypeBuilder.AddMemberWithValue("VM_PROT_DEFAULT", MACHO_VM_PROT_DEFAULT);
	// protTypeBuilder.AddMemberWithValue("VM_PROT_ALL", MACHO_VM_PROT_ALL);
	protTypeBuilder.AddMemberWithValue("VM_PROT_NO_CHANGE", MACHO_VM_PROT_NO_CHANGE);
	protTypeBuilder.AddMemberWithValue("VM_PROT_COPY_OR_WANTS_COPY", MACHO_VM_PROT_COPY);
	// protTypeBuilder.AddMemberWithValue("VM_PROT_WANTS_COPY", MACHO_VM_PROT_WANTS_COPY);
	Ref<Enumeration> protTypeEnum = protTypeBuilder.Finalize();

	Ref<Type> protTypeEnumType = Type::EnumerationType(nullptr, protTypeEnum, 4, false);
	std::string protTypeEnumName = "vm_prot_t";
	std::string protTypeEnumId = Type::GenerateAutoTypeId("macho", protTypeEnumName);
	DefineType(protTypeEnumId, protTypeEnumName, protTypeEnumType);

	EnumerationBuilder segFlagsTypeBuilder;
	segFlagsTypeBuilder.AddMemberWithValue("SG_HIGHVM", SG_HIGHVM);
	segFlagsTypeBuilder.AddMemberWithValue("SG_FVMLIB", SG_FVMLIB);
	segFlagsTypeBuilder.AddMemberWithValue("SG_NORELOC", SG_NORELOC);
	segFlagsTypeBuilder.AddMemberWithValue("SG_PROTECTED_VERSION_1", SG_PROTECTED_VERSION_1);
	Ref<Enumeration> segFlagsTypeEnum = segFlagsTypeBuilder.Finalize();

	Ref<Type> segFlagsTypeEnumType = Type::EnumerationType(nullptr, segFlagsTypeEnum, 4, false);
	std::string segFlagsTypeEnumName = "sg_flags_t";
	std::string segFlagsTypeEnumId = Type::GenerateAutoTypeId("macho", segFlagsTypeEnumName);
	DefineType(segFlagsTypeEnumId, segFlagsTypeEnumName, segFlagsTypeEnumType);

	StructureBuilder loadSegmentCommandBuilder;
	loadSegmentCommandBuilder.AddMember(Type::NamedType(this, QualifiedName("load_command_type_t")), "cmd");
	loadSegmentCommandBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	loadSegmentCommandBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 16), "segname");
	loadSegmentCommandBuilder.AddMember(Type::IntegerType(4, false), "vmaddr");
	loadSegmentCommandBuilder.AddMember(Type::IntegerType(4, false), "vmsize");
	loadSegmentCommandBuilder.AddMember(Type::IntegerType(4, false), "fileoff");
	loadSegmentCommandBuilder.AddMember(Type::IntegerType(4, false), "filesize");
	loadSegmentCommandBuilder.AddMember(Type::NamedType(this, QualifiedName("vm_prot_t")), "maxprot");
	loadSegmentCommandBuilder.AddMember(Type::NamedType(this, QualifiedName("vm_prot_t")), "initprot");
	loadSegmentCommandBuilder.AddMember(Type::IntegerType(4, false), "nsects");
	loadSegmentCommandBuilder.AddMember(Type::NamedType(this, QualifiedName("sg_flags_t")), "flags");
	Ref<Structure> loadSegmentCommandStruct = loadSegmentCommandBuilder.Finalize();
	QualifiedName loadSegmentCommandName = std::string("segment_command");
	std::string loadSegmentCommandTypeId = Type::GenerateAutoTypeId("macho", loadSegmentCommandName);
	Ref<Type> loadSegmentCommandType = Type::StructureType(loadSegmentCommandStruct);
	DefineType(loadSegmentCommandTypeId, loadSegmentCommandName, loadSegmentCommandType);

	StructureBuilder loadSegmentCommand64Builder;
	loadSegmentCommand64Builder.AddMember(Type::NamedType(this, QualifiedName("load_command_type_t")), "cmd");
	loadSegmentCommand64Builder.AddMember(Type::IntegerType(4, false), "cmdsize");
	loadSegmentCommand64Builder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 16), "segname");
	loadSegmentCommand64Builder.AddMember(Type::IntegerType(8, false), "vmaddr");
	loadSegmentCommand64Builder.AddMember(Type::IntegerType(8, false), "vmsize");
	loadSegmentCommand64Builder.AddMember(Type::IntegerType(8, false), "fileoff");
	loadSegmentCommand64Builder.AddMember(Type::IntegerType(8, false), "filesize");
	loadSegmentCommand64Builder.AddMember(Type::NamedType(this, QualifiedName("vm_prot_t")), "maxprot");
	loadSegmentCommand64Builder.AddMember(Type::NamedType(this, QualifiedName("vm_prot_t")), "initprot");
	loadSegmentCommand64Builder.AddMember(Type::IntegerType(4, false), "nsects");
	loadSegmentCommand64Builder.AddMember(Type::NamedType(this, QualifiedName("sg_flags_t")), "flags");
	Ref<Structure> loadSegmentCommand64Struct = loadSegmentCommand64Builder.Finalize();
	QualifiedName loadSegment64CommandName = std::string("segment_command_64");
	std::string loadSegment64CommandTypeId = Type::GenerateAutoTypeId("macho", loadSegment64CommandName);
	Ref<Type> loadSegment64CommandType = Type::StructureType(loadSegmentCommand64Struct);
	DefineType(loadSegment64CommandTypeId, loadSegment64CommandName, loadSegment64CommandType);

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
	QualifiedName sectionName = std::string("section");
	std::string sectionTypeId = Type::GenerateAutoTypeId("macho", sectionName);
	Ref<Type> sectionType = Type::StructureType(sectionStruct);
	DefineType(sectionTypeId, sectionName, sectionType);

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
	QualifiedName section64Name = std::string("section_64");
	std::string section64TypeId = Type::GenerateAutoTypeId("macho", section64Name);
	Ref<Type> section64Type = Type::StructureType(section64Struct);
	DefineType(section64TypeId, section64Name, section64Type);

	StructureBuilder symtabBuilder;
	symtabBuilder.AddMember(Type::NamedType(this, QualifiedName("load_command_type_t")), "cmd");
	symtabBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	symtabBuilder.AddMember(Type::IntegerType(4, false), "symoff");
	symtabBuilder.AddMember(Type::IntegerType(4, false), "nsyms");
	symtabBuilder.AddMember(Type::IntegerType(4, false), "stroff");
	symtabBuilder.AddMember(Type::IntegerType(4, false), "strsize");
	Ref<Structure> symtabStruct = symtabBuilder.Finalize();
	QualifiedName symtabName = std::string("symtab");
	std::string symtabTypeId = Type::GenerateAutoTypeId("macho", symtabName);
	Ref<Type> symtabType = Type::StructureType(symtabStruct);
	DefineType(symtabTypeId, symtabName, symtabType);

	StructureBuilder dynsymtabBuilder;
	dynsymtabBuilder.AddMember(Type::NamedType(this, QualifiedName("load_command_type_t")), "cmd");
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
	QualifiedName dynsymtabName = std::string("dysymtab");
	std::string dynsymtabTypeId = Type::GenerateAutoTypeId("macho", dynsymtabName);
	Ref<Type> dynsymtabType = Type::StructureType(dynsymtabStruct);
	DefineType(dynsymtabTypeId, dynsymtabName, dynsymtabType);

	StructureBuilder uuidBuilder;
	uuidBuilder.AddMember(Type::NamedType(this, QualifiedName("load_command_type_t")), "cmd");
	uuidBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	uuidBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, false), 16), "uuid");
	Ref<Structure> uuidStruct = uuidBuilder.Finalize();
	QualifiedName uuidName = std::string("uuid");
	std::string uuidTypeId = Type::GenerateAutoTypeId("macho", uuidName);
	Ref<Type> uuidType = Type::StructureType(uuidStruct);
	DefineType(uuidTypeId, uuidName, uuidType);

	StructureBuilder linkeditDataBuilder;
	linkeditDataBuilder.AddMember(Type::NamedType(this, QualifiedName("load_command_type_t")), "cmd");
	linkeditDataBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	linkeditDataBuilder.AddMember(Type::IntegerType(4, false), "dataoff");
	linkeditDataBuilder.AddMember(Type::IntegerType(4, false), "datasize");
	Ref<Structure> linkeditDataStruct = linkeditDataBuilder.Finalize();
	QualifiedName linkeditDataName = std::string("linkedit_data");
	std::string linkeditDataTypeId = Type::GenerateAutoTypeId("macho", linkeditDataName);
	Ref<Type> linkeditDataType = Type::StructureType(linkeditDataStruct);
	DefineType(linkeditDataTypeId, linkeditDataName, linkeditDataType);

	StructureBuilder encryptionInfoBuilder;
	encryptionInfoBuilder.AddMember(Type::NamedType(this, QualifiedName("load_command_type_t")), "cmd");
	encryptionInfoBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	encryptionInfoBuilder.AddMember(Type::IntegerType(4, false), "cryptoff");
	encryptionInfoBuilder.AddMember(Type::IntegerType(4, false), "cryptsize");
	encryptionInfoBuilder.AddMember(Type::IntegerType(4, false), "cryptid");
	Ref<Structure> encryptionInfoStruct = encryptionInfoBuilder.Finalize();
	QualifiedName encryptionInfoName = std::string("encryption_info");
	std::string encryptionInfoTypeId = Type::GenerateAutoTypeId("macho", encryptionInfoName);
	Ref<Type> encryptionInfoType = Type::StructureType(encryptionInfoStruct);
	DefineType(encryptionInfoTypeId, encryptionInfoName, encryptionInfoType);

	StructureBuilder versionMinBuilder;
	versionMinBuilder.AddMember(Type::NamedType(this, QualifiedName("load_command_type_t")), "cmd");
	versionMinBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	versionMinBuilder.AddMember(Type::IntegerType(4, false), "version");
	versionMinBuilder.AddMember(Type::IntegerType(4, false), "sdk");
	Ref<Structure> versionMinStruct = versionMinBuilder.Finalize();
	QualifiedName versionMinName = std::string("version_min");
	std::string versionMinTypeId = Type::GenerateAutoTypeId("macho", versionMinName);
	Ref<Type> versionMinType = Type::StructureType(versionMinStruct);
	DefineType(versionMinTypeId, versionMinName, versionMinType);

	StructureBuilder dyldInfoBuilder;
	dyldInfoBuilder.AddMember(Type::NamedType(this, QualifiedName("load_command_type_t")), "cmd");
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
	QualifiedName dyldInfoName = std::string("dyld_info");
	std::string dyldInfoTypeId = Type::GenerateAutoTypeId("macho", dyldInfoName);
	Ref<Type> dyldInfoType = Type::StructureType(dyldInfoStruct);
	DefineType(dyldInfoTypeId, dyldInfoName, dyldInfoType);

	StructureBuilder dylibBuilder;
	dylibBuilder.AddMember(Type::IntegerType(4, false), "name");
	dylibBuilder.AddMember(Type::IntegerType(4, false), "timestamp");
	dylibBuilder.AddMember(Type::IntegerType(4, false), "current_version");
	dylibBuilder.AddMember(Type::IntegerType(4, false), "compatibility_version");
	Ref<Structure> dylibStruct = dylibBuilder.Finalize();
	QualifiedName dylibName = std::string("dylib");
	std::string dylibTypeId = Type::GenerateAutoTypeId("macho", dylibName);
	Ref<Type> dylibType = Type::StructureType(dylibStruct);
	DefineType(dylibTypeId, dylibName, dylibType);

	StructureBuilder dylibCommandBuilder;
	dylibCommandBuilder.AddMember(Type::NamedType(this, QualifiedName("load_command_type_t")), "cmd");
	dylibCommandBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	dylibCommandBuilder.AddMember(Type::NamedType(this, QualifiedName("dylib")), "dylib");
	Ref<Structure> dylibCommandStruct = dylibCommandBuilder.Finalize();
	QualifiedName dylibCommandName = std::string("dylib_command");
	std::string dylibCommandTypeId = Type::GenerateAutoTypeId("macho", dylibCommandName);
	Ref<Type> dylibCommandType = Type::StructureType(dylibCommandStruct);
	DefineType(dylibCommandTypeId, dylibCommandName, dylibCommandType);

	StructureBuilder filesetEntryCommandBuilder;
	filesetEntryCommandBuilder.AddMember(Type::NamedType(this, QualifiedName("load_command_type_t")), "cmd");
	filesetEntryCommandBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	filesetEntryCommandBuilder.AddMember(Type::IntegerType(8, false), "vmaddr");
	filesetEntryCommandBuilder.AddMember(Type::IntegerType(8, false), "fileoff");
	filesetEntryCommandBuilder.AddMember(Type::IntegerType(4, false), "entry_id");
	filesetEntryCommandBuilder.AddMember(Type::IntegerType(4, false), "reserved");
	Ref<Structure> filesetEntryCommandStruct = filesetEntryCommandBuilder.Finalize();
	QualifiedName filesetEntryCommandName = std::string("fileset_entry_command");
	std::string filesetEntryCommandTypeId = Type::GenerateAutoTypeId("macho", filesetEntryCommandName);
	Ref<Type> filesetEntryCommandType = Type::StructureType(filesetEntryCommandStruct);
	DefineType(filesetEntryCommandTypeId, filesetEntryCommandName, filesetEntryCommandType);

	StructureBuilder unixThreadCommandBuilder;
	unixThreadCommandBuilder.AddMember(Type::NamedType(this, QualifiedName("load_command_type_t")), "cmd");
	unixThreadCommandBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
	unixThreadCommandBuilder.AddMember(Type::IntegerType(4, false), "flavor");
	unixThreadCommandBuilder.AddMember(Type::IntegerType(4, false), "count");
	// The 'state' field is intentionally ignored.
	Ref<Structure> unixThreadCommandStruct = unixThreadCommandBuilder.Finalize();
	QualifiedName unixThreadCommandName = std::string("unix_thread_command");
	std::string unixThreadCommandTypeId = Type::GenerateAutoTypeId("macho", unixThreadCommandName);
	Ref<Type> unixThreadCommandType = Type::StructureType(unixThreadCommandStruct);
	DefineType(unixThreadCommandTypeId, unixThreadCommandName, unixThreadCommandType);

	// Technically the header is executable, but there shouldn't reasonably be code in the header.
	AddAutoSegment(textSegOffset, sizeofcmds + 0x20, 0, sizeofcmds + 0x20, SegmentReadable);
	AddAutoSection("kernelcache_header", textSegOffset, sizeofcmds + 0x20, ReadOnlyDataSectionSemantics);

	if (m_parseOnly)
		return true;

	DefineDataVariable(textSegOffset, Type::NamedType(this, QualifiedName("mach_header_64")));
	DefineAutoSymbol(
		new Symbol(DataSymbol, "kernelcache_header", textSegOffset, LocalBinding));

	try
	{
		reader.Seek(sizeof(mach_header_64));
		size_t sectionNum = 0;
		for (size_t i = 0; i < ncmds; i++)
		{
			load_command load;
			uint64_t curOffset = reader.GetOffset();
			load.cmd = reader.Read32();
			load.cmdsize = reader.Read32();
			uint64_t nextOffset = curOffset + load.cmdsize;
			switch (load.cmd)
			{
			case LC_SEGMENT:
			{
				DefineDataVariable(reader.GetOffset() + textSegOffset, Type::NamedType(this, QualifiedName("segment_command")));
				reader.SeekRelative(5 * 8);
				size_t numSections = reader.Read32();
				reader.SeekRelative(4);
				for (size_t j = 0; j < numSections; j++)
				{
					DefineDataVariable(
						reader.GetOffset() + textSegOffset, Type::NamedType(this, QualifiedName("section")));
					DefineAutoSymbol(new Symbol(DataSymbol,
						"__macho_section::kernelcache[" + std::to_string(sectionNum++) + "]",
						reader.GetOffset() + textSegOffset, LocalBinding));
					reader.SeekRelative((8 * 8) + 4);
				}
				break;
			}
			case LC_SEGMENT_64:
			{
				DefineDataVariable(curOffset + textSegOffset, Type::NamedType(this, QualifiedName("segment_command_64")));
				reader.SeekRelative(7 * 8);
				size_t numSections = reader.Read32();
				reader.SeekRelative(4);
				for (size_t j = 0; j < numSections; j++)
				{
					DefineDataVariable(
						reader.GetOffset() + textSegOffset, Type::NamedType(this, QualifiedName("section_64")));
					DefineAutoSymbol(new Symbol(DataSymbol,
						"__macho_section_64::kernelcache[" + std::to_string(sectionNum++) + "]",
						reader.GetOffset() + textSegOffset, LocalBinding));
					reader.SeekRelative(10 * 8);
				}
				break;
			}
			case LC_SYMTAB:
				DefineDataVariable(curOffset + textSegOffset, Type::NamedType(this, QualifiedName("symtab")));
				break;
			case LC_DYSYMTAB:
				DefineDataVariable(curOffset + textSegOffset, Type::NamedType(this, QualifiedName("dysymtab")));
				break;
			case LC_UUID:
				DefineDataVariable(curOffset + textSegOffset, Type::NamedType(this, QualifiedName("uuid")));
				break;
			case LC_ID_DYLIB:
			case LC_LOAD_DYLIB:
			case LC_REEXPORT_DYLIB:
			case LC_LOAD_WEAK_DYLIB:
			case LC_LOAD_UPWARD_DYLIB:
				DefineDataVariable(curOffset + textSegOffset, Type::NamedType(this, QualifiedName("dylib_command")));
				if (load.cmdsize - 24 <= 150)
					DefineDataVariable(
						curOffset + textSegOffset + 24, Type::ArrayType(Type::IntegerType(1, true), load.cmdsize - 24));
				break;
			case LC_CODE_SIGNATURE:
			case LC_SEGMENT_SPLIT_INFO:
			case LC_FUNCTION_STARTS:
			case LC_DATA_IN_CODE:
			case LC_DYLIB_CODE_SIGN_DRS:
			case LC_DYLD_EXPORTS_TRIE:
			case LC_DYLD_CHAINED_FIXUPS:
				DefineDataVariable(curOffset + textSegOffset, Type::NamedType(this, QualifiedName("linkedit_data")));
				break;
			case LC_ENCRYPTION_INFO:
				DefineDataVariable(curOffset + textSegOffset, Type::NamedType(this, QualifiedName("encryption_info")));
				break;
			case LC_VERSION_MIN_MACOSX:
			case LC_VERSION_MIN_IPHONEOS:
				DefineDataVariable(curOffset + textSegOffset, Type::NamedType(this, QualifiedName("version_min")));
				break;
			case LC_DYLD_INFO:
			case LC_DYLD_INFO_ONLY:
				DefineDataVariable(curOffset + textSegOffset, Type::NamedType(this, QualifiedName("dyld_info")));
				break;
			case LC_FILESET_ENTRY:
				DefineDataVariable(curOffset + textSegOffset, Type::NamedType(this, QualifiedName("fileset_entry_command")));
				break;
			case LC_UNIXTHREAD:
			{
				DefineDataVariable(
					curOffset + textSegOffset, Type::NamedType(this, QualifiedName("unix_thread_command")));
				reader.SeekRelative(4);
				uint32_t count = reader.Read32();
				DefineDataVariable(reader.GetOffset() + textSegOffset, Type::ArrayType(Type::IntegerType(8, true), count));
				break;
			}
			default:
				DefineDataVariable(curOffset + textSegOffset, Type::NamedType(this, QualifiedName("load_command")));
				break;
			}

			DefineAutoSymbol(new Symbol(DataSymbol,
				"__macho_load_command::kernelcache[" + std::to_string(i) + "]", curOffset + textSegOffset,
				LocalBinding));
			reader.Seek(nextOffset);
		}
	}
	catch (ReadException&)
	{
		LogErrorF("Error when applying Mach-O header types at {:#x}", textSegOffset);
	}

	return InitController();
}

bool KernelCacheView::InitController()
{
	// OK, we have the primary shared cache file, now let's add the entries.
	auto kernelCacheBuilder = KernelCacheBuilder(this);
	auto kernelCache = kernelCacheBuilder.Finalize();

	// TODO: Here we should have all the regions and what not for the virtual memory populated, I think it might be a good idea
	// TODO: To verify the regions are here and pointing at valid file accessor mappings, to make diagnosing issues quicker.

	{
		BinaryReader reader(GetParentView());
		reader.Seek(0x10);
		uint64_t ncmds = reader.Read32();
		uint64_t offset = 0x20;
		for (uint64_t i = 0; i < ncmds; i++)
		{
			reader.Seek(offset);
			uint64_t cmd = reader.Read32();
			uint64_t cmdsize = reader.Read32();

			if (cmd == LC_FILESET_ENTRY)
			{
				fileset_entry_command fileset_entry;
				reader.Seek(offset);
				reader.Read(&fileset_entry, sizeof(fileset_entry_command));
				reader.Seek(offset + fileset_entry.nameEntryOffsetFromBaseOfCommand);
				auto name = reader.ReadCString(1000);
				kernelCache.ProcessEntryImage(this, name, fileset_entry);
			}

			if (cmd == LC_DYLD_CHAINED_FIXUPS)
			{
				linkedit_data_command chained_fixups;
				reader.Seek(offset);
				reader.Read(&chained_fixups, sizeof(linkedit_data_command));

				kernelCache.ProcessRelocations(this, chained_fixups);
			}

			offset += cmdsize;
		}
	}

	auto cacheController = KernelCacheController::Initialize(*this, std::move(kernelCache));

	{
		auto logger = m_logger;
		// Load up all the symbols into the named symbols lookup map.
		// NOTE: We do this on a separate thread as image & region loading does not consult this.
		WorkerPriorityEnqueue([logger, cacheController]() {
			auto& kernelCache = cacheController->GetCache();
			auto startTime = std::chrono::high_resolution_clock::now();
			kernelCache.ProcessSymbols();
			auto endTime = std::chrono::high_resolution_clock::now();
			std::chrono::duration<double> elapsed = endTime - startTime;
			logger->LogInfoF("Processing {} symbols took {:.3f} seconds (separate thread)", kernelCache.GetSymbols().size(), elapsed.count());
		});
	}

	Ref<Settings> settings = GetLoadSettings(GetTypeName());
	// Users can adjust which images are loaded by default using the `loader.dsc.autoLoadPattern` setting.
	std::string autoLoadPattern = ".*libsystem_c.dylib";
	if (settings && settings->Contains("loader.kc.autoLoadPattern"))
		autoLoadPattern = settings->Get<std::string>("loader.kc.autoLoadPattern", this);
	m_logger->LogDebugF("Loading images using pattern: {:?}", autoLoadPattern);

	{
		// TODO: Refusing to add undo action "Added section libsystem_c.dylib::__macho_header", there is literally
		// TODO: no way around this warning as undo actions are implicit with user sections, for more detail see:
		// TODO:	- https://github.com/Vector35/binaryninja-api/issues/6742
		// TODO:	- https://github.com/Vector35/binaryninja-api/issues/6289
		// Load all images that match the `autoLoadPattern`.
		auto startTime = std::chrono::high_resolution_clock::now();
		size_t loadedImages = 0;
		std::regex autoLoadRegex(autoLoadPattern);
		for (const auto& [_, image] : cacheController->GetCache().GetImages())
			if (std::regex_match(image.GetName(), autoLoadRegex))
				if (cacheController->ApplyImage(*this, image))
					++loadedImages;
		auto endTime = std::chrono::high_resolution_clock::now();
		std::chrono::duration<double> elapsed = endTime - startTime;
		m_logger->LogInfoF("Automatically loading {} images took {:.3f} seconds", loadedImages, elapsed.count());
	}

	if (auto loadedImageMetadata = GetParentView()->QueryMetadata("KernelCacheLoadedImages"))
	{
		auto loadedImageList = loadedImageMetadata->GetArray();
		for (const auto & imageAddrMeta : loadedImageList)
		{
			auto imageAddr = imageAddrMeta->GetUnsignedInteger();
			const auto& image = cacheController->GetCache().GetImageAt(imageAddr);
			if (image)
			{
				cacheController->ApplyImage(*this, *image);
			}
		}
	}

	return true;
}
