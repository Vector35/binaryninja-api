#include "universaltransform.h"
#include "machoview.h"
#include <cstring>

using namespace BinaryNinja;
using namespace std;


const map<pair<cpu_type_t, cpu_subtype_t>, string>& UniversalTransform::GetArchitectures()
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


string UniversalTransform::ArchitectureToString(cpu_type_t cpuType, cpu_subtype_t cpuSubType, bool& is64Bit)
{
	const map<pair<cpu_type_t, cpu_subtype_t>, string>& cpuArchNames = UniversalTransform::GetArchitectures();

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


bool UniversalTransform::ParseHeaders(Ref<BinaryView> data, FatHeader& fatHeader, vector<FatArch64>& fatArchEntries, bool& isFat64, string& errorMsg)
{
	if (data->GetLength() < 8)
	{
		errorMsg = "Universal (Fat Mach-O): file too small";
		return false;
	}

	uint8_t header[8];
	if (data->Read(header, 0, 8) < 8)
	{
		errorMsg = "Universal (Fat Mach-O): failed to read header";
		return false;
	}

	uint32_t magic = ToBE32(*(uint32_t*)header);
	if ((magic != FAT_MAGIC) && (magic != FAT_MAGIC_64))
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
			fatArch.reserved = 0;
		}

		// Mask away cpu subtype capability bits
		fatArch.cpusubtype &= ~MACHO_CPU_SUBTYPE_MASK;
		fatArchEntries.push_back(fatArch);
	}

	return true;
}


UniversalTransform::UniversalTransform() :
	Transform(DecodeTransform, TransformCapabilities(TransformSupportsDetection | TransformSupportsContext), "Universal", "Universal (Fat Mach-O)", "Container")
{
}


bool UniversalTransform::Decode(const DataBuffer& input, DataBuffer& output, const map<string, DataBuffer>& params)
{
	// Create a temporary BinaryView for parsing
	auto fileMetadata = new FileMetadata();
	auto rawView = new BinaryData(fileMetadata, input);

	FatHeader fatHeader;
	vector<FatArch64> fatArchEntries;
	bool isFat64;
	string errorMsg;

	if (!ParseHeaders(rawView, fatHeader, fatArchEntries, isFat64, errorMsg))
	{
		LogError("Universal: %s", errorMsg.c_str());
		return false;
	}

	if (fatArchEntries.empty())
	{
		LogError("Universal: no architectures found");
		return false;
	}

	// Look for architecture parameter
	string targetArch;
	if (auto archParam = params.find("architecture"); archParam != params.end())
		targetArch = string(reinterpret_cast<const char*>(archParam->second.GetData()), archParam->second.GetLength());

	// If no target specified, extract first architecture
	const FatArch64* targetEntry = nullptr;
	if (targetArch.empty())
	{
		targetEntry = &fatArchEntries[0];
	}
	else
	{
		// Find matching architecture
		for (const auto& entry : fatArchEntries)
		{
			bool is64Bit;
			string archName = ArchitectureToString(entry.cputype, entry.cpusubtype, is64Bit);
			if (archName == targetArch)
			{
				targetEntry = &entry;
				break;
			}
		}

		if (!targetEntry)
		{
			LogError("Universal: architecture '%s' not found", targetArch.c_str());
			return false;
		}
	}

	// Validate bounds
	if (targetEntry->offset > input.GetLength() || targetEntry->size > input.GetLength() - targetEntry->offset)
	{
		LogError("Universal: architecture data extends beyond file bounds");
		return false;
	}

	// Extract the Mach-O slice
	output = DataBuffer(static_cast<const uint8_t*>(input.GetData()) + targetEntry->offset, static_cast<size_t>(targetEntry->size));
	return true;
}


bool UniversalTransform::DecodeWithContext(Ref<TransformContext> context, const map<string, DataBuffer>& params)
{
	if (!context || !context->GetInput())
		return false;

	Ref<BinaryView> input = context->GetInput();
	FatHeader fatHeader;
	vector<FatArch64> fatArchEntries;
	bool isFat64;
	string errorMsg;

	if (!ParseHeaders(input, fatHeader, fatArchEntries, isFat64, errorMsg))
	{
		LogError("Universal: %s", errorMsg.c_str());
		return false;
	}

	if (fatArchEntries.empty())
	{
		LogError("Universal: no architectures found");
		return false;
	}

	// Phase 1: Discovery - enumerate available architectures
	if (!context->HasAvailableFiles())
	{
		vector<string> architectures;
		for (const auto& entry : fatArchEntries)
		{
			bool is64Bit;
			string archName = ArchitectureToString(entry.cputype, entry.cpusubtype, is64Bit);
			architectures.push_back(archName);
		}

		// TODO: It is surprising that this is UniversalTransform's responsibility.
		if (!BinaryNinja::IsUIEnabled())
		{
			// When headless, filter to the preferred architecture if one is configured.
			vector<string> archPref = context->GetSettings()->Get<vector<string>>("files.universal.architecturePreference");
			if (auto result = find_first_of(archPref.begin(), archPref.end(), architectures.begin(), architectures.end()); result != archPref.end())
			{
				size_t archIndex = find(architectures.begin(), architectures.end(), *result) - architectures.begin();
				context->SetAvailableFiles({architectures[archIndex]});
				return false;
			}

			// Load the first architecture if no preference is found.
			if (archPref.empty() && architectures.size())
			{
				context->SetAvailableFiles({architectures[0]});
				return false;
			}
		}

		context->SetAvailableFiles(architectures);
		return false;
	}

	// Phase 2: Extraction - extract requested architectures
	vector<string> requestedFiles = context->GetRequestedFiles();
	if (requestedFiles.empty())
		return false;

	// Build a map of architecture names to entries
	map<string, const FatArch64*> archMap;
	for (const auto& entry : fatArchEntries)
	{
		bool is64Bit;
		string archName = ArchitectureToString(entry.cputype, entry.cpusubtype, is64Bit);
		archMap[archName] = &entry;
	}

	bool complete = true;
	for (const string& requestedArch : requestedFiles)
	{
		auto itr = archMap.find(requestedArch);
		if (itr == archMap.end())
		{
			string msg = "Universal: requested architecture '" + requestedArch + "' not found";
			context->SetChild(DataBuffer(), requestedArch, TransformFailure, msg);
			complete = false;
			continue;
		}

		const FatArch64* entry = itr->second;

		// Validate bounds
		if (entry->offset > input->GetLength() || entry->size > input->GetLength() - entry->offset)
		{
			string msg = "Universal: architecture data extends beyond file bounds";
			context->SetChild(DataBuffer(), requestedArch, TransformFailure, msg);
			complete = false;
			continue;
		}

		// Extract the Mach-O slice
		DataBuffer sliceData;
		sliceData.SetSize(static_cast<size_t>(entry->size));
		if (input->Read(sliceData.GetData(), entry->offset, static_cast<size_t>(entry->size)) < entry->size)
		{
			string msg = "Universal: failed to read architecture data";
			context->SetChild(DataBuffer(), requestedArch, TransformFailure, msg);
			complete = false;
			continue;
		}

		// Create child context with the extracted slice
		context->SetChild(sliceData, requestedArch, TransformSuccess, "", true);
	}

	return complete;
}


bool UniversalTransform::Encode(const DataBuffer& input, DataBuffer& output, const map<string, DataBuffer>& params)
{
	return false;
}


bool UniversalTransform::CanDecode(Ref<BinaryView> input) const
{
	if (input->GetLength() < 4)
		return false;

	uint8_t magic[4];
	if (input->Read(magic, 0, 4) < 4)
		return false;

	uint32_t magicValue = ToBE32(*(uint32_t*)magic);
	return (magicValue == FAT_MAGIC) || (magicValue == FAT_MAGIC_64);
}


void BinaryNinja::InitUniversalTransform()
{
	static UniversalTransform universalXform;
	Transform::Register(&universalXform);
}
