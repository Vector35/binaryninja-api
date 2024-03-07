#include <stdlib.h>
#include <string.h>
#include <cstdint>
#include <map>
#include "fatmachoview.h"
#include "machoview.h"

using namespace BinaryNinja;
using namespace std;


struct fat_type
{
	string name;
	string long_name;
	cpu_type_t cputype;
	cpu_subtype_t cpusubtype;
};


static vector<fat_type>* g_recognizedFatTypes;

static const map<cpu_type_t, cpu_subtype_t> g_allSubtypeMap
{
	{MACHO_CPU_TYPE_X86, MACHO_CPU_SUBTYPE_X86_ALL},
	{MACHO_CPU_TYPE_X86_64, MACHO_CPU_SUBTYPE_X86_64_ALL},
	{MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_ALL},
	{MACHO_CPU_TYPE_ARM64, MACHO_CPU_SUBTYPE_ARM64_ALL},
	{MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_ALL},
	{MACHO_CPU_TYPE_POWERPC64, MACHO_CPU_SUBTYPE_POWERPC_ALL}
};


FatMachoViewType::FatMachoViewType(const string& name, const string& long_name, cpu_type_t cputype, cpu_subtype_t cpusubtype) : BinaryViewType(name, long_name), m_cputype(cputype), m_cpusubtype(cpusubtype)
{

}


static bool FindMostSpecificCpuTypeSubtype(cpu_type_t cputype, cpu_subtype_t cpusubtype, cpu_subtype_t& outType)
{
	// Anything exact is most specific
	for (const auto& type : *g_recognizedFatTypes)
	{
		if (type.cputype == cputype && type.cpusubtype == cpusubtype)
		{
			outType = type.cpusubtype;
			return true;
		}
	}
	// Then, any -all arch that matches
	for (const auto& type : *g_recognizedFatTypes)
	{
		if (type.cputype == cputype && type.cpusubtype == g_allSubtypeMap.at(cputype))
		{
			outType = type.cpusubtype;
			return true;
		}
	}
	// Else, no match
	return false;
}


static bool ExtractFatArchForCPU(BinaryView* data, fat_arch_64& arch, cpu_type_t cputype, cpu_subtype_t cpusubtype)
{
	DataBuffer sig = data->ReadBuffer(0, 4);
	if (sig.GetLength() != 4)
		return false;

	uint32_t magic = ToBE32(*(uint32_t*)sig.GetData());
	if ((magic != FAT_MAGIC) && (magic != FAT_MAGIC_64))
		return false;

	bool fat64 = (magic == FAT_MAGIC_64);

	fat_header header;
	BinaryReader reader(data);

	// According to docs, Fat files are always BigEndian
	reader.SetEndianness(BigEndian);
	header.magic = reader.Read32();
	header.nfat_arch = reader.Read32();

	// Malformed header, too many archs
	size_t expectSize = header.nfat_arch * (fat64 ? 32 /* sizeof(fat_arch_64) */ : 20 /* sizeof(fat_arch) */) + 8 /* sizeof(fat_header) */;
	if (expectSize > data->GetLength())
	{
		return false;
	}

	// Because Mach-O files can "hide" extra archs after the end for weird legacy reasons,
	// we shouldn't assume the header has the right number of archs
	while (true)
	{
		// Just use a fat_arch_64 struct since we read manually and it can hold both sizes
		fat_arch_64 iarch;
		try
		{
			if (fat64)
			{
				iarch.cputype = reader.Read32();
				iarch.cpusubtype = reader.Read32();
				iarch.offset = reader.Read64();
				iarch.size = reader.Read64();
				iarch.align = reader.Read32();
				iarch.reserved = reader.Read32();
			}
			else
			{
				iarch.cputype = reader.Read32();
				iarch.cpusubtype = reader.Read32();
				iarch.offset = reader.Read32();
				iarch.size = reader.Read32();
				iarch.align = reader.Read32();
			}
		}
		catch (ReadException &)
		{
			return false;
		}

		if (iarch.cputype == 0)
		{
			// Probably the end
			break;
		}

		if (iarch.offset + iarch.size > data->GetLength())
		{
			// Malformed
			break;
		}

		if (iarch.cputype != cputype)
		{
			continue;
		}

		// Make sure the passed subtype is the most specific, otherwise two different views
		// will try to display the same slice
		cpu_subtype_t mostSpecific;
		if (!FindMostSpecificCpuTypeSubtype(iarch.cputype, iarch.cpusubtype, mostSpecific))
		{
			continue;
		}
		if (cpusubtype == mostSpecific)
		{
			arch = iarch;
			return true;
		}
	}

	// Don't have this specific subtype
	return false;
}


Ref<BinaryViewType> FatViewTypeForData(Ref<BinaryData> data)
{
	vector<Ref<BinaryViewType>> types = BinaryViewType::GetViewTypesForData(data);
	for (Ref<BinaryViewType> type : types)
	{
		// Ignore raw binary data views
		if (type->GetName() == "Raw")
		{
			continue;
		}

		// Make sure that the slice is still itself a valid mach-o
		if (!type->IsTypeValidForData(data))
		{
			continue;
		}

		return type;
	}
	return nullptr;
}


Ref<BinaryView> FatMachoViewType::Create(BinaryView* data)
{
	fat_arch_64 arch;
	if (!ExtractFatArchForCPU(data, arch, m_cputype, m_cpusubtype))
		return nullptr;

	DataBuffer buffer = data->ReadBuffer(arch.offset, arch.size);
	Ref<BinaryData> newData = new BinaryData(data->GetFile(), std::move(buffer));

	try
	{
		// Update the view to this specific arch so it doesn't conflict when saving/loading
		return new MachoView(GetName(), newData);
	}
	catch (std::exception&)
	{
		return nullptr;
	}
}


bool FatMachoViewType::IsTypeValidForData(BinaryView* data)
{
	// Enable this BinaryViewType for existing databases only
	if (!data->GetFile()->IsBackedByDatabase())
		return false;

	fat_arch_64 arch;
	if (!ExtractFatArchForCPU(data, arch, m_cputype, m_cpusubtype))
		return false;

	// MachoView::IsMacho only considers the magic header, so we can load only that
	DataBuffer buffer = data->ReadBuffer(arch.offset, 4);
	Ref<BinaryData> newData = new BinaryData(data->GetFile(), std::move(buffer));
	Ref<BinaryViewType> attemptedViewType = FatViewTypeForData(newData);

	return attemptedViewType;
}


void BinaryNinja::InitFatMachoViewType()
{
	// Need a pointer because this is called from a constructor before g_recognizedFatTypes is loaded.
	g_recognizedFatTypes = new vector<fat_type>
	{
		{"Fat Mach-O x86_64", "Fat Mach-O x86_64", MACHO_CPU_TYPE_X86_64, MACHO_CPU_SUBTYPE_X86_64_ALL},
		{"Fat Mach-O x86", "Fat Mach-O x86", MACHO_CPU_TYPE_X86, MACHO_CPU_SUBTYPE_X86_ALL},

		{"Fat Mach-O arm64e", "Fat Mach-O arm64e", MACHO_CPU_TYPE_ARM64, MACHO_CPU_SUBTYPE_ARM64E},
		{"Fat Mach-O arm64v8", "Fat Mach-O arm64v8", MACHO_CPU_TYPE_ARM64, MACHO_CPU_SUBTYPE_ARM64_V8},
		{"Fat Mach-O arm64", "Fat Mach-O arm64", MACHO_CPU_TYPE_ARM64, MACHO_CPU_SUBTYPE_ARM64_ALL},
		{"Fat Mach-O arm64_32", "Fat Mach-O arm64_32", MACHO_CPU_TYPE_ARM64_32, MACHO_CPU_SUBTYPE_ARM64_32_V8},
		{"Fat Mach-O armv8", "Fat Mach-O armv8", MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_V8},
		{"Fat Mach-O armv7em", "Fat Mach-O armv7em", MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_V7EM},
		{"Fat Mach-O armv7m", "Fat Mach-O armv7m", MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_V7M},
		{"Fat Mach-O armv7s", "Fat Mach-O armv7s", MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_V7S},
		{"Fat Mach-O armv7k", "Fat Mach-O armv7k", MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_V7K},
		{"Fat Mach-O armv7", "Fat Mach-O armv7", MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_V7},
		{"Fat Mach-O armv6m", "Fat Mach-O armv6m", MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_V6M},
		{"Fat Mach-O armv6", "Fat Mach-O armv6", MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_V6},
		{"Fat Mach-O armv5tej", "Fat Mach-O armv5tej", MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_V5TEJ},
		{"Fat Mach-O armv4t", "Fat Mach-O armv4t", MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_V4T},
		{"Fat Mach-O arm xscale", "Fat Mach-O arm xscale", MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_XSCALE},
		{"Fat Mach-O arm", "Fat Mach-O arm", MACHO_CPU_TYPE_ARM, MACHO_CPU_SUBTYPE_ARM_ALL},
		{"Fat Mach-O ppc64", "Fat Mach-O ppc64", MACHO_CPU_TYPE_POWERPC64, MACHO_CPU_SUBTYPE_POWERPC_ALL},
		{"Fat Mach-O ppc970", "Fat Mach-O ppc970", MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_970},
		{"Fat Mach-O ppc7450", "Fat Mach-O ppc7450", MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_7450},
		{"Fat Mach-O ppc7400", "Fat Mach-O ppc7400", MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_7400},
		{"Fat Mach-O ppc750", "Fat Mach-O ppc750", MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_750},
		{"Fat Mach-O ppc620", "Fat Mach-O ppc620", MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_620},
		{"Fat Mach-O ppc604e", "Fat Mach-O ppc604e", MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_604e},
		{"Fat Mach-O ppc604", "Fat Mach-O ppc604", MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_604},
		{"Fat Mach-O ppc603ev", "Fat Mach-O ppc603ev", MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_603ev},
		{"Fat Mach-O ppc603e", "Fat Mach-O ppc603e", MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_603e},
		{"Fat Mach-O ppc603", "Fat Mach-O ppc603", MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_603},
		{"Fat Mach-O ppc602", "Fat Mach-O ppc602", MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_602},
		{"Fat Mach-O ppc601", "Fat Mach-O ppc601", MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_601},
		{"Fat Mach-O ppc", "Fat Mach-O ppc", MACHO_CPU_TYPE_POWERPC, MACHO_CPU_SUBTYPE_POWERPC_ALL}
	};

	for (const auto& type : *g_recognizedFatTypes)
	{
		BinaryViewType::Register(new FatMachoViewType(type.name, type.long_name, type.cputype, type.cpusubtype));
	}
}
