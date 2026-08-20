#include <stdlib.h>
#include <string.h>
#include <cstdint>
#include <map>
#ifndef _MSC_VER
#include <cxxabi.h>
#endif
#include "universalview.h"
#include "universaltransform.h"
#include "machoview.h"
#include "rapidjsonwrapper.h"

using namespace BinaryNinja;
using namespace std;


static UniversalViewType* g_universalViewType = nullptr;


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
			"sorted" : false,
			"default" : [],
			"description" : "Architectures to prefer when loading Universal (fat) Mach-O archives, in order of priority. Determines which architecture is pre-selected in the architecture picker, or loaded automatically when prompting is set to 'automatic' or 'never'.",
			"ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
			})");

	const map<pair<cpu_type_t, cpu_subtype_t>, string>& cpuArchNames = UniversalTransform::GetArchitectures();
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
	return UniversalTransform::ParseHeaders(data, fatHeader, fatArchEntries, isFat64, errorMsg);
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
		string archDesc = UniversalTransform::ArchitectureToString(entry.cputype, entry.cpusubtype, is64Bit);
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
