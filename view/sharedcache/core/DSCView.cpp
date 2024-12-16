//
// Created by kat on 5/23/23.
//

/*
 * If you're here looking for the code to load caches, out of luck.
 *
 * The VIEW_NAME is essentially a blank slate that only knows how to deserialize and reserialize itself
 * 	based on some metadata encoded in it.
 *
 * The actual controller logic that does _all_ of the image loading is invoked via API -> SharedCache.cpp
 *
 * */

#include "DSCView.h"
#include "view/macho/machoview.h"
#include "SharedCache.h"

using namespace BinaryNinja;

/*
 * DSCRawView is a "fake" parent view that the child view actually fills with data on init.
 *
 * This is the 'magic' that makes this sort of horrible "serialize the file headers and then refill the parent view"
 * work.
 *
 * This throws errors on deser due to undo actions, but it still works.
 * */
DSCRawView::DSCRawView(const std::string& typeName, BinaryView* data, bool parseOnly) :
	BinaryView(typeName, data->GetFile(), data)
{
	// This is going to load _only_ the dyld header of the loaded file.
	// This written region will be immediately overwritten on image loading by SharedCache.cpp
	GetFile()->SetFilename(data->GetFile()->GetOriginalFilename());
	uint32_t size;
	GetParentView()->Read(&size, 16, 4);
	size += 8;
	AddAutoSegment(0, size, 0, size, SegmentReadable);
	GetParentView()->WriteBuffer(0, GetParentView()->ReadBuffer(0, size));
}

bool DSCRawView::Init()
{
	return true;
}

DSCRawViewType::DSCRawViewType() : BinaryViewType("DSCRaw", "DSCRaw") {}

BinaryNinja::Ref<BinaryNinja::BinaryView> DSCRawViewType::Create(BinaryView* data)
{
	return new DSCRawView("DSCRaw", data, false);
}

BinaryNinja::Ref<BinaryNinja::BinaryView> DSCRawViewType::Parse(BinaryView* data)
{
	return new DSCRawView("DSCRaw", data, true);
}

bool DSCRawViewType::IsTypeValidForData(BinaryNinja::BinaryView* data)
{
	// Always return false here.
	// This view pretty much exists to keep a bunch of internal core logic happy as it expects certain things
	// from our view's parent that we need to control, and cannot control on a standard raw view.

	// IIRC an example of this was the need to add more data past the end of the original file.

	// in ios16 caches, the primary file can be like 100kb while a standard image will easily break 1MB

	// I actually should check if the stuff related to non-file-backed-segments changes the need for this,
	// but at the time it was created (2022) it was necessary.
	return false;
}


DSCView::DSCView(const std::string& typeName, BinaryView* data, bool parseOnly) :
	BinaryView(typeName, data->GetFile(), data), m_parseOnly(parseOnly)
{
	CreateLogger("SharedCache");
	CreateLogger("SharedCache.ObjC");
}

DSCView::~DSCView()
{
	if (!m_parseOnly)
		MMappedFileAccessor::CloseAll(GetFile()->GetSessionId());
}

enum DSCPlatform {
	DSCPlatformMacOS = 1,
	DSCPlatformiOS = 2,
};

bool DSCView::Init()
{
	uint32_t platform;
	GetParentView()->Read(&platform, 0xd8, 4);
	char magic[17];
	GetParentView()->Read(&magic, 0, 16);
	magic[16] = 0;
	std::string os;
	if (platform == DSCPlatformMacOS)
	{
		os = "mac";
	}
	else if (platform == DSCPlatformiOS)
	{
		os = "ios";
	}
	else
	{
		LogError("Unknown platform: %d", platform);
		return false;
	}
	if (std::string(magic) == "dyld_v1   arm64" || std::string(magic) == "dyld_v1  arm64e")
	{
		SetDefaultPlatform(Platform::GetByName(os + "-aarch64"));
		SetDefaultArchitecture(Architecture::GetByName("aarch64"));
	}
	else if (std::string(magic) == "dyld_v1  x86_64")
	{
		SetDefaultPlatform(Platform::GetByName(os + "-x86_64"));
		SetDefaultArchitecture(Architecture::GetByName("x86_64"));
	}
	else
	{
		LogError("Unknown magic: %s", magic);
		return false;
	}
	QualifiedNameAndType headerType;
	std::string err;

	ParseTypeString("\n"
		"\tstruct dyld_cache_header\n"
		"\t{\n"
		"\t\tchar magic[16];\t\t\t\t\t // e.g. \"dyld_v0    i386\"\n"
		"\t\tuint32_t mappingOffset;\t\t\t // file offset to first dyld_cache_mapping_info\n"
		"\t\tuint32_t mappingCount;\t\t\t // number of dyld_cache_mapping_info entries\n"
		"\t\tuint32_t imagesOffsetOld;\t\t // UNUSED: moved to imagesOffset to prevent older dsc_extarctors from crashing\n"
		"\t\tuint32_t imagesCountOld;\t\t // UNUSED: moved to imagesCount to prevent older dsc_extarctors from crashing\n"
		"\t\tuint64_t dyldBaseAddress;\t\t // base address of dyld when cache was built\n"
		"\t\tuint64_t codeSignatureOffset;\t // file offset of code signature blob\n"
		"\t\tuint64_t codeSignatureSize;\t\t // size of code signature blob (zero means to end of file)\n"
		"\t\tuint64_t slideInfoOffsetUnused;\t // unused.  Used to be file offset of kernel slid info\n"
		"\t\tuint64_t slideInfoSizeUnused;\t // unused.  Used to be size of kernel slid info\n"
		"\t\tuint64_t localSymbolsOffset;\t // file offset of where local symbols are stored\n"
		"\t\tuint64_t localSymbolsSize;\t\t // size of local symbols information\n"
		"\t\tuint8_t uuid[16];\t\t\t\t // unique value for each shared cache file\n"
		"\t\tuint64_t cacheType;\t\t\t\t // 0 for development, 1 for production // Kat: , 2 for iOS 16?\n"
		"\t\tuint32_t branchPoolsOffset;\t\t // file offset to table of uint64_t pool addresses\n"
		"\t\tuint32_t branchPoolsCount;\t\t // number of uint64_t entries\n"
		"\t\tuint64_t accelerateInfoAddr;\t // (unslid) address of optimization info\n"
		"\t\tuint64_t accelerateInfoSize;\t // size of optimization info\n"
		"\t\tuint64_t imagesTextOffset;\t\t // file offset to first dyld_cache_image_text_info\n"
		"\t\tuint64_t imagesTextCount;\t\t // number of dyld_cache_image_text_info entries\n"
		"\t\tuint64_t patchInfoAddr;\t\t\t // (unslid) address of dyld_cache_patch_info\n"
		"\t\tuint64_t patchInfoSize;\t // Size of all of the patch information pointed to via the dyld_cache_patch_info\n"
		"\t\tuint64_t otherImageGroupAddrUnused;\t // unused\n"
		"\t\tuint64_t otherImageGroupSizeUnused;\t // unused\n"
		"\t\tuint64_t progClosuresAddr;\t\t\t // (unslid) address of list of program launch closures\n"
		"\t\tuint64_t progClosuresSize;\t\t\t // size of list of program launch closures\n"
		"\t\tuint64_t progClosuresTrieAddr;\t\t // (unslid) address of trie of indexes into program launch closures\n"
		"\t\tuint64_t progClosuresTrieSize;\t\t // size of trie of indexes into program launch closures\n"
		"\t\tuint32_t platform;\t\t\t\t\t // platform number (macOS=1, etc)\n"
		"\t\tuint32_t formatVersion : 8,\t\t\t // dyld3::closure::kFormatVersion\n"
		"\t\t\tdylibsExpectedOnDisk : 1,  // dyld should expect the dylib exists on disk and to compare inode/mtime to see if cache is valid\n"
		"\t\t\tsimulator : 1,\t\t\t   // for simulator of specified platform\n"
		"\t\t\tlocallyBuiltCache : 1,\t   // 0 for B&I built cache, 1 for locally built cache\n"
		"\t\t\tbuiltFromChainedFixups : 1,\t // some dylib in cache was built using chained fixups, so patch tables must be used for overrides\n"
		"\t\t\tpadding : 20;\t\t\t\t // TBD\n"
		"\t\tuint64_t sharedRegionStart;\t\t // base load address of cache if not slid\n"
		"\t\tuint64_t sharedRegionSize;\t\t // overall size required to map the cache and all subCaches, if any\n"
		"\t\tuint64_t maxSlide;\t\t\t\t // runtime slide of cache can be between zero and this value\n"
		"\t\tuint64_t dylibsImageArrayAddr;\t // (unslid) address of ImageArray for dylibs in this cache\n"
		"\t\tuint64_t dylibsImageArraySize;\t // size of ImageArray for dylibs in this cache\n"
		"\t\tuint64_t dylibsTrieAddr;\t\t // (unslid) address of trie of indexes of all cached dylibs\n"
		"\t\tuint64_t dylibsTrieSize;\t\t // size of trie of cached dylib paths\n"
		"\t\tuint64_t otherImageArrayAddr;\t // (unslid) address of ImageArray for dylibs and bundles with dlopen closures\n"
		"\t\tuint64_t otherImageArraySize;\t // size of ImageArray for dylibs and bundles with dlopen closures\n"
		"\t\tuint64_t otherTrieAddr;\t // (unslid) address of trie of indexes of all dylibs and bundles with dlopen closures\n"
		"\t\tuint64_t otherTrieSize;\t // size of trie of dylibs and bundles with dlopen closures\n"
		"\t\tuint32_t mappingWithSlideOffset;\t\t // file offset to first dyld_cache_mapping_and_slide_info\n"
		"\t\tuint32_t mappingWithSlideCount;\t\t\t // number of dyld_cache_mapping_and_slide_info entries\n"
		"\t\tuint64_t dylibsPBLStateArrayAddrUnused;\t // unused\n"
		"\t\tuint64_t dylibsPBLSetAddr;\t\t\t\t // (unslid) address of PrebuiltLoaderSet of all cached dylibs\n"
		"\t\tuint64_t programsPBLSetPoolAddr;\t\t // (unslid) address of pool of PrebuiltLoaderSet for each program\n"
		"\t\tuint64_t programsPBLSetPoolSize;\t\t // size of pool of PrebuiltLoaderSet for each program\n"
		"\t\tuint64_t programTrieAddr;\t\t\t\t // (unslid) address of trie mapping program path to PrebuiltLoaderSet\n"
		"\t\tuint32_t programTrieSize;\n"
		"\t\tuint32_t osVersion;\t\t\t\t// OS Version of dylibs in this cache for the main platform\n"
		"\t\tuint32_t altPlatform;\t\t\t// e.g. iOSMac on macOS\n"
		"\t\tuint32_t altOsVersion;\t\t\t// e.g. 14.0 for iOSMac\n"
		"\t\tuint64_t swiftOptsOffset;\t\t// file offset to Swift optimizations header\n"
		"\t\tuint64_t swiftOptsSize;\t\t\t// size of Swift optimizations header\n"
		"\t\tuint32_t subCacheArrayOffset;\t// file offset to first dyld_subcache_entry\n"
		"\t\tuint32_t subCacheArrayCount;\t// number of subCache entries\n"
		"\t\tuint8_t symbolFileUUID[16];\t\t// unique value for the shared cache file containing unmapped local symbols\n"
		"\t\tuint64_t rosettaReadOnlyAddr;\t// (unslid) address of the start of where Rosetta can add read-only/executable data\n"
		"\t\tuint64_t rosettaReadOnlySize;\t// maximum size of the Rosetta read-only/executable region\n"
		"\t\tuint64_t rosettaReadWriteAddr;\t// (unslid) address of the start of where Rosetta can add read-write data\n"
		"\t\tuint64_t rosettaReadWriteSize;\t// maximum size of the Rosetta read-write region\n"
		"\t\tuint32_t imagesOffset;\t\t\t// file offset to first dyld_cache_image_info\n"
		"\t\tuint32_t imagesCount;\t\t\t// number of dyld_cache_image_info entries\n"
		"\t};", headerType, err);

	Ref<Settings> settings = GetLoadSettings(GetTypeName());

	if (!settings)
	{
		Ref<Settings> programSettings = Settings::Instance();
		programSettings->Set("analysis.workflows.functionWorkflow", "core.function.dsc", this);
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
	QualifiedName dynsymtabName = std::string("dynsymtab");
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

	std::vector<SharedCacheCore::MemoryRegion> regionsMappedIntoMemory;
	if (auto meta = GetParentView()->GetParentView()->QueryMetadata(SharedCacheCore::SharedCacheMetadataTag))
	{
		std::string data = GetParentView()->GetParentView()->GetStringMetadata(SharedCacheCore::SharedCacheMetadataTag);
		std::stringstream ss;
		ss.str(data);
		rapidjson::Document result(rapidjson::kObjectType);

		result.Parse(data.c_str());

		if (result.HasMember("metadataVersion"))
		{
			if (result["metadataVersion"].GetInt() != METADATA_VERSION)
			{
				LogError("Shared cache metadata version mismatch: expected %d, got %d", METADATA_VERSION,
					result["metadataVersion"].GetInt());
				return false;
			}
		}
		else
		{
			LogError("Shared cache metadata version not found");
			return false;
		}
		for (auto& imgV : result["regionsMappedIntoMemory"].GetArray())
		{
			SharedCacheCore::MemoryRegion region;
			region.LoadFromValue(imgV);
			regionsMappedIntoMemory.push_back(region);
		}

		std::unordered_map<uint64_t, std::string> imageStartToInstallName;
		// key "m_imageStarts"
		for (auto& imgV : result["m_imageStarts"].GetArray())
		{
			std::string name = imgV.GetArray()[0].GetString();
			uint64_t addr = imgV.GetArray()[1].GetUint64();
			imageStartToInstallName[addr] = name;
		}

		std::vector<std::pair<uint64_t, std::vector<std::pair<uint64_t, std::pair<BNSymbolType, std::string>>>>> exportInfos;

		for (const auto& obj1 : result["exportInfos"].GetArray())
		{
			std::vector<std::pair<uint64_t, std::pair<BNSymbolType, std::string>>> innerVec;
			for (const auto& obj2 : obj1["value"].GetArray())
			{
				std::pair<BNSymbolType, std::string> innerPair = { (BNSymbolType)obj2["val1"].GetUint64(), obj2["val2"].GetString() };
				innerVec.push_back({ obj2["key"].GetUint64(), innerPair });
			}

			exportInfos.push_back({obj1["key"].GetUint64(), innerVec});
		}
		// We need to re-map data located in the Raw (parent parent) viewtype to the DSCRaw (parent) viewtype.
		for (auto region : regionsMappedIntoMemory)
		{
			GetParentView()->AddUserSegment(
				region.rawViewOffsetIfLoaded, region.size, region.rawViewOffsetIfLoaded, region.size, region.flags);
			GetParentView()->WriteBuffer(
				region.rawViewOffsetIfLoaded, GetParentView()->GetParentView()->ReadBuffer(region.rawViewOffsetIfLoaded, region.size));
		}

		BeginBulkModifySymbols();
		for (const auto & [imageBaseAddr, exportList] : exportInfos)
		{
			std::vector<Ref<Symbol>> symbolsList;
			for (const auto & [exportAddr, exportTypeAndName] : exportList)
			{
				symbolsList.push_back(new Symbol(exportTypeAndName.first, exportTypeAndName.second, exportAddr));
			}

			auto typelib = GetTypeLibrary(imageStartToInstallName[imageBaseAddr]);

			for (const auto& symbol : symbolsList)
			{
				if (!IsValidOffset(symbol->GetAddress()))
					continue;
				if (typelib)
				{
					auto type = typelib->GetNamedObject(symbol->GetRawName());
					if (type)
					{
						DefineAutoSymbolAndVariableOrFunction(GetDefaultPlatform(), symbol, type);
						continue;
					}
				}
				DefineAutoSymbol(symbol);
			}
		}
		EndBulkModifySymbols();
	}

	// uint32_t at 0x10 is offset to mapping table.
	// first mapping struct in that table is base of primary
	// first uint64_t in that struct is the base address of the primary
	// double gpv here because DSCRaw explicitly stops at the start of this mapping table
	uint64_t basePointer = 0;
	GetParentView()->GetParentView()->Read(&basePointer, 16, 4);
	if (basePointer == 0)
	{
		LogError("Failed to read base pointer");
		return false;
	}
	uint64_t primaryBase = 0;
	GetParentView()->GetParentView()->Read(&primaryBase, basePointer, 8);
	if (primaryBase == 0)
	{
		LogError("Failed to read primary base at 0x%llx", basePointer);
		return false;
	}

	AddAutoSegment(primaryBase, 0x200, 0, 0x200, SegmentReadable);
	AddAutoSection("__dsc_header", primaryBase, 0x200, ReadOnlyCodeSectionSemantics);
	DefineType("dyld_cache_header", headerType.name, headerType.type);
	DefineAutoSymbolAndVariableOrFunction(GetDefaultPlatform(), new Symbol(DataSymbol, "primary_cache_header", primaryBase), headerType.type);

	return true;
}


DSCViewType::DSCViewType() : BinaryViewType(VIEW_NAME, VIEW_NAME) {}

BinaryNinja::Ref<BinaryNinja::BinaryView> DSCViewType::Create(BinaryNinja::BinaryView* data)
{
	Ref<BinaryView> rawViewRef = new DSCRawView("DSCRawView", data, false);
	return new DSCView(VIEW_NAME, rawViewRef, false);
}


Ref<Settings> DSCViewType::GetLoadSettingsForData(BinaryView* data)
{
	Ref<BinaryView> viewRef = Parse(data);
	if (!viewRef || !viewRef->Init())
	{
		LogError("View type '%s' could not be created", GetName().c_str());
		return nullptr;
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

	Ref<Settings> programSettings = Settings::Instance();
	programSettings->Set("analysis.workflows.functionWorkflow", "core.function.dsc", viewRef);

	settings->RegisterSetting("loader.dsc.processCFStrings",
		R"({
		"title" : "Process CFString Metadata",
		"type" : "boolean",
		"default" : true,
		"description" : "Processes CoreFoundation strings, applying string values from encoded metadata"
		})");

	settings->RegisterSetting("loader.dsc.autoLoadLibSystem",
		R"({
		"title" : "Auto-Load libSystem",
		"type" : "boolean",
		"default" : true,
		"description" : "Whether to automatically load libsystem_c.dylib. This image contains frequently used noreturn symbols, and not loading it will result in frequently incorrect control flows."
		})");

	settings->RegisterSetting("loader.dsc.processObjC",
		R"({
		"title" : "Process Objective-C Metadata",
		"type" : "boolean",
		"default" : true,
		"description" : "Processes Objective-C metadata, applying class and method names from encoded metadata"
		})");

	settings->RegisterSetting("loader.dsc.autoLoadObjCStubRequirements",
		R"({
		"title" : "Auto-Load Objective-C Stub Requirements",
		"type" : "boolean",
		"default" : true,
		"description" : "Automatically loads segments required for inlining Objective-C stubs. Recommended you keep this on."
		})");

	settings->RegisterSetting("loader.dsc.autoLoadStubsAndDyldData",
		R"({
		"title" : "Auto-Load Stub Islands",
		"type" : "boolean",
		"default" : true,
		"description" : "Automatically loads stub and dylddata regions that contain just branches and pointers. These are required for resolving stub names, and performance impact is minimal. Recommended you keep this on."
		})");

	settings->RegisterSetting("loader.dsc.allowLoadingLinkeditSegments",
		R"({
		"title" : "Allow Loading __LINKEDIT Segments",
		"type" : "boolean",
		"default" : false,
		"description" : "Allow mapping __LINKEDIT segments. These are large regions of symbol data that are automatically processed by BinaryNinja without the need for mapping. On newer caches, __LINKEDIT for all images may end up merged and be >300MB in size. This will likely cause severe performance degradation with _zero_ benefit."
		})");

	settings->RegisterSetting("loader.dsc.processFunctionStarts",
		R"({
			"title" : "Process Mach-O Function Starts Tables",
			"type" : "boolean",
			"default" : true,
			"description" : "Add function starts sourced from the Function Starts tables to the core for analysis."
			})");

	// Merge existing load settings if they exist. This allows for the selection of a specific object file from a Mach-O
	// Universal file. The 'Universal' BinaryViewType generates a schema with 'loader.universal.architectures'. This
	// schema contains an appropriate 'Mach-O' load schema for selecting a specific object file. The embedded schema
	// contains 'loader.macho.universalImageOffset'.
	Ref<Settings> loadSettings = viewRef->GetLoadSettings(GetName());
	if (loadSettings && !loadSettings->IsEmpty())
		settings->DeserializeSchema(loadSettings->SerializeSchema());

	return settings;
}


BinaryNinja::Ref<BinaryNinja::BinaryView> DSCViewType::Parse(BinaryNinja::BinaryView* data)
{
	return new DSCView(VIEW_NAME, new DSCRawView("DSCRawView", data, true), true);
}

bool DSCViewType::IsTypeValidForData(BinaryNinja::BinaryView* data)
{
	if (!data)
		return false;

	DataBuffer sig = data->ReadBuffer(data->GetStart(), 4);
	if (sig.GetLength() != 4)
		return false;

	const char* magic = (char*)sig.GetData();
	if (strncmp(magic, "dyld", 4) == 0)
		return true;

	return false;
}
