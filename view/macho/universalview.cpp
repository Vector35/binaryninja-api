#include <stdlib.h>
#include <string.h>
#include <cstdint>
#include <map>
#ifndef _MSC_VER
#include <cxxabi.h>
#endif
#include "universalview.h"
#include "machoview.h"
#include "rapidjsonwrapper.h"

using namespace BinaryNinja;
using namespace std;


static UniversalViewType* g_universalViewType = nullptr;


const map<pair<cpu_type_t, cpu_subtype_t>, string>& UniversalViewType::GetArchitectures()
{
	static map<pair<cpu_type_t, cpu_subtype_t>, string> g_cpuArchNames =
	{
		{{MACHO_CPU_TYPE_VAX, 0}, "vax"},
		{{MACHO_CPU_TYPE_MC680x0, 0}, "mc680x0"},
		{{MACHO_CPU_TYPE_X86, 0}, "x86"},
		{{MACHO_CPU_TYPE_X86, MACHO_CPU_SUBTYPE_X86_ALL}, "x86"},
		{{MACHO_CPU_TYPE_X86, MACHO_CPU_SUBTYPE_X86_ARCH1}, "x86 (Arch1)"},
		{{MACHO_CPU_TYPE_X86_64, 0}, "x86_64"},
		{{MACHO_CPU_TYPE_X86_64, MACHO_CPU_SUBTYPE_X86_64_ALL}, "x86_64"},
		{{MACHO_CPU_TYPE_X86_64, MACHO_CPU_SUBTYPE_X86_64_H}, "x86_64 (Haswell)"},
		{{MACHO_CPU_TYPE_MIPS, 0}, "mips"},
		{{MACHO_CPU_TYPE_MC98000, 0}, "mc98000"},
		{{MACHO_CPU_TYPE_HPPA, 0}, "hppa"},
		{{MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_ALL}, "arm"},
		{{MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_V4T}, "armv4t"},
		{{MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_V6}, "armv6"},
		{{MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_V5TEJ}, "armv5tej"},
		{{MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_XSCALE}, "arm (XScale)"},
		{{MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_V7}, "armv7"},
		{{MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_V7F}, "armv7f"},
		{{MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_V7S}, "armv7s"},
		{{MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_V7K}, "armv7k"},
		{{MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_V8}, "armv8"},
		{{MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_V6M}, "armv6m"},
		{{MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_V7M}, "armv7m"},
		{{MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_V7EM}, "armv7em"},
		{{MACHO_CPU_TYPE_ARM64, MACHO_CPU_SUBTYPE_ARM64_ALL}, "arm64"},
		{{MACHO_CPU_TYPE_ARM64, MACHO_CPU_SUBTYPE_ARM64_V8}, "arm64v8"},
		{{MACHO_CPU_TYPE_ARM64, MACHO_CPU_SUBTYPE_ARM64E}, "arm64e"},
		{{MACHO_CPU_TYPE_ARM64_32, MACHO_CPU_SUBTYPE_ARM64_32_ALL}, "arm64_32"},
		{{MACHO_CPU_TYPE_ARM64_32, MACHO_CPU_SUBTYPE_ARM64_32_V8}, "arm64_32v8"},
		{{MACHO_CPU_TYPE_MC88000, 0}, "mc88000"},
		{{MACHO_CPU_TYPE_SPARC, 0}, "sparc"},
		{{MACHO_CPU_TYPE_I860, 0}, "i860"},
		{{MACHO_CPU_TYPE_ALPHA, 0}, "alpha"},
		{{MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_ALL}, "ppc"},
		{{MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_601}, "ppc601"},
		{{MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_602}, "ppc602"},
		{{MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_603}, "ppc603"},
		{{MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_603e}, "ppc603e"},
		{{MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_603ev}, "ppc603ev"},
		{{MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_604}, "ppc604"},
		{{MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_604e}, "ppc604e"},
		{{MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_620}, "ppc620"},
		{{MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_750}, "ppc750"},
		{{MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_7400}, "ppc7400"},
		{{MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_7450}, "ppc7450"},
		{{MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_970}, "ppc970"},
		{{MACHO_CPU_TYPE_POWERPC64, 0}, "ppc64"}
	};

	return g_cpuArchNames;
}


string UniversalViewType::ArchitectureToString(cpu_type_t cpuType, cpu_subtype_t cpuSubType, bool& is64Bit)
{
	const map<pair<cpu_type_t, cpu_subtype_t>, string>& cpuArchNames = GetArchitectures();

	switch(cpuType)
	{
		case MACHO_CPU_TYPE_X86_64:
		case MACHO_CPU_TYPE_ARM64:
		case MACHO_CPU_TYPE_ARM64_32:
		case MACHO_CPU_TYPE_POWERPC64:
			is64Bit = true;
			break;
		default:
			is64Bit = false;
			break;
	}

	auto itr = cpuArchNames.find({cpuType, cpuSubType});
	if (itr != cpuArchNames.end())
		return itr->second;

	itr = cpuArchNames.find({cpuType, 0});
	if (itr != cpuArchNames.end())
		return itr->second;

	return "Unknown";
}


void BinaryNinja::InitUniversalViewType()
{
	static UniversalViewType type;
	BinaryViewType::Register(&type);
	g_universalViewType = &type;

	Ref<Settings> settings = Settings::Instance();
	settings->RegisterSetting("files.universal.architecturePreference",
			R"({
			"title" : "Universal Mach-O Architecture Preference",
			"type" : "array",
			"elementType" : "string",
			"sorted" : false,
			"default" : [],
			"description" : "Specify an architecture preference for automatic loading of a Mach-O file from a Universal archive. By default, the first object file in the listing is loaded.",
			"ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
			})");

	const map<pair<cpu_type_t, cpu_subtype_t>, string>& cpuArchNames = UniversalViewType::GetArchitectures();
	set<string> names;
	for (const auto& [key, name] : cpuArchNames)
		names.insert(name);
	vector<string> archNames(names.begin(), names.end());
	settings->UpdateProperty("files.universal.architecturePreference", "enum", archNames);
}


Ref<BinaryView> UniversalViewType::Create(BinaryView* data)
{
	try
	{
		return new UniversalView(data);
	}
	catch (std::exception&)
	{
		return nullptr;
	}
}


bool UniversalViewType::IsTypeValidForData(BinaryView* data)
{
	DataBuffer sig = data->ReadBuffer(0, 4);
	if (sig.GetLength() != 4)
		return false;

	uint32_t magic = ToBE32(*(uint32_t*)sig.GetData());
	if ((magic == FAT_MAGIC) || (magic == FAT_MAGIC_64))
		return true;

	return false;
}


bool UniversalViewType::ParseHeaders(BinaryView* data, FatHeader& fatHeader, vector<FatArch64>& fatArchEntries, bool& isFat64, string& errorMsg)
{
	if (!IsTypeValidForData(data))
	{
		errorMsg = "Universal (Fat Mach-O): invalid signature";
		return false;
	}

	BinaryReader reader(data);
	reader.SetEndianness(BigEndian);
	fatHeader.magic = reader.Read32();
	fatHeader.nfat_arch = reader.Read32();

	isFat64 = (fatHeader.magic == FAT_MAGIC_64);
	size_t requiredFatHeaderSize = fatHeader.nfat_arch * (isFat64 ? 32 : 20) + 8;
	if (requiredFatHeaderSize > data->GetLength())
	{
		errorMsg = "Universal (Fat Mach-O): header truncated";
		return false;
	}

	for (size_t i = 0; i < fatHeader.nfat_arch; i++)
	{
		FatArch64 fatArch;
		if (isFat64)
		{
			fatArch.cputype = reader.Read32();
			fatArch.cpusubtype = reader.Read32();
			fatArch.offset = reader.Read64();
			fatArch.size = reader.Read64();
			fatArch.align = reader.Read32();
			fatArch.reserved = reader.Read32();
		}
		else
		{
			fatArch.cputype = reader.Read32();
			fatArch.cpusubtype = reader.Read32();
			fatArch.offset = reader.Read32();
			fatArch.size = reader.Read32();
			fatArch.align = reader.Read32();
		}

		// Mask away cpu subtype capability bits
		fatArch.cpusubtype &= ~MACHO_CPU_SUBTYPE_MASK;
		fatArchEntries.push_back(fatArch);
	}

	return true;
}


Ref<Settings> UniversalViewType::GetLoadSettingsForData(BinaryView* data)
{
	FatHeader fatHeader;
	vector<FatArch64> fatArchEntries;
	bool isFat64;
	string errorMsg;
	if (!g_universalViewType->ParseHeaders(data, fatHeader, fatArchEntries, isFat64, errorMsg))
		return nullptr;

	if (!fatArchEntries.size()) // TODO other validation?
		return nullptr;

	Ref<Settings> settings = Settings::Instance(GetUniqueIdentifierString());
	settings->RegisterGroup("loader", "Load Options");
	settings->RegisterSetting("loader.universal.architectures",
			R"({
			"title" : "Universal Mach-O Multi-Architecture Binary Description",
			"type" : "string",
			"default" : "[]",
			"description" : "Describes the available object files in the Universal Multi-Architecture binary.",
			"readOnly" : true
			})");

	Ref<Settings> entrySettings = Settings::Instance(GetUniqueIdentifierString());
	entrySettings->RegisterGroup("loader", "Load Options");
	entrySettings->RegisterSetting("loader.macho.universalImageOffset",
			R"({
			"title" : "Universal Mach-O Object File Offset",
			"type" : "number",
			"default" : 0,
			"description" : "The offset to the object file within the Universal Mach-O file.",
			"minValue" : 0,
			"maxValue" : 18446744073709551615,
			"readOnly" : true
			})");

	rapidjson::Document entries(rapidjson::kArrayType);
	int count = 0;
	for (const auto& entry : fatArchEntries)
	{
		rapidjson::Value result(rapidjson::kObjectType);
		bool is64Bit;
		string archDesc = ArchitectureToString(entry.cputype, entry.cpusubtype, is64Bit);
		string bitDesc = is64Bit ? "64-bit" : "32-bit";
		result.AddMember("id", count++, entries.GetAllocator());
		result.AddMember("architecture", archDesc, entries.GetAllocator());
		result.AddMember("is64Bit", is64Bit, entries.GetAllocator());
		result.AddMember("binaryViewType", "Mach-O", entries.GetAllocator());
		result.AddMember("description", "Mach-O " + bitDesc + " executable " + archDesc, entries.GetAllocator());
		result.AddMember("offset", ToLE64(entry.offset), entries.GetAllocator());
		result.AddMember("size", ToLE64(entry.size), entries.GetAllocator());
		entrySettings->UpdateProperty("loader.macho.universalImageOffset", "default", ToLE64(entry.offset));
		result.AddMember("loadSchema", entrySettings->SerializeSchema(), entries.GetAllocator());
		entries.PushBack(result, entries.GetAllocator());
	}

	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	entries.Accept(writer);

	settings->UpdateProperty("loader.universal.architectures", "default", buffer.GetString());

	return settings;
}


UniversalView::UniversalView(BinaryView* data, bool parseOnly): BinaryView("Universal", data->GetFile(), data)
{
	FatHeader fatHeader;
	vector<FatArch64> fatArchEntries;
	bool isFat64;
	string errorMsg;
	if (!g_universalViewType->ParseHeaders(data, fatHeader, fatArchEntries, isFat64, errorMsg))
		throw MachoFormatException(errorMsg);

	if (parseOnly)
		return;

	// Add Universal file header type info
	StructureBuilder fatHeaderBuilder;
	fatHeaderBuilder.AddMember(Type::IntegerType(4, false), "magic");
	fatHeaderBuilder.AddMember(Type::IntegerType(4, false), "nfat_arch");
	Ref<Structure> fatHeaderStruct = fatHeaderBuilder.Finalize();
	QualifiedName headerName = string("fat_header");
	string headerTypeId = Type::GenerateAutoTypeId("macho", headerName);
	Ref<Type> fatHeaderType = Type::StructureType(fatHeaderStruct);
	QualifiedName rawHeaderName = DefineType(headerTypeId, headerName, fatHeaderType);
	DefineDataVariable(0, Type::NamedType(this, rawHeaderName));
	DefineAutoSymbol(new Symbol(DataSymbol, "__fat_header", 0, LocalBinding));

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
	QualifiedName rawCpuTypeEnumName = DefineType(cpuTypeEnumId, cpuTypeEnumName, cpuTypeEnumType);

	StructureBuilder fatArchBuilder;
	fatArchBuilder.AddMember(Type::NamedType(this, rawCpuTypeEnumName), "cputype");
	fatArchBuilder.AddMember(Type::IntegerType(4, false), "cpusubtype");
	if (isFat64)
	{
		fatArchBuilder.AddMember(Type::IntegerType(8, false), "offset");
		fatArchBuilder.AddMember(Type::IntegerType(8, false), "size");
	}
	else
	{
		fatArchBuilder.AddMember(Type::IntegerType(4, false), "offset");
		fatArchBuilder.AddMember(Type::IntegerType(4, false), "size");
	}
	fatArchBuilder.AddMember(Type::IntegerType(4, false), "align");
	if (isFat64)
		fatArchBuilder.AddMember(Type::IntegerType(4, false), "reserved");
	Ref<Structure> fatArchStruct = fatArchBuilder.Finalize();
	QualifiedName fatArchName = isFat64 ? string("fat_arch_64") : string("fat_arch");
	string fatArchTypeId = Type::GenerateAutoTypeId("macho", fatArchName);
	Ref<Type> fatArchType = Type::StructureType(fatArchStruct);
	QualifiedName rawFatArchName = DefineType(fatArchTypeId, fatArchName, fatArchType);
	DefineDataVariable(8, Type::ArrayType(Type::NamedType(this, rawFatArchName), fatHeader.nfat_arch));
	DefineAutoSymbol(new Symbol(DataSymbol, "__fat_arch_entries", 8, LocalBinding));
}


UniversalView::~UniversalView()
{
}


bool UniversalView::Init()
{
	// Disable analysis modules
	// TODO: for now Raw and Universal views do this; possibly refactor
	if (!m_file->IsBackedByDatabase(GetTypeName()))
	{
		Settings::Instance()->Set("analysis.linearSweep.autorun", false, this);
		Settings::Instance()->Set("analysis.signatureMatcher.autorun", false, this);
		Settings::Instance()->Set("analysis.pointerSweep.autorun", false, this);
	}

	AddAutoSegment(0, GetParentView()->GetLength(), 0, GetParentView()->GetLength(), SegmentReadable | SegmentWritable);
	return true;
}
