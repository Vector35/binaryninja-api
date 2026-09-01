#include "Utility.h"
#include "binaryninjaapi.h"
#include "view/macho/machoview.h"

using namespace BinaryNinja;

int64_t readSLEB128(const uint8_t*& current, const uint8_t* end)
{
	uint8_t cur;
	int64_t value = 0;
	size_t shift = 0;
	while (current != end)
	{
		cur = *current++;
		value |= (cur & 0x7f) << shift;
		shift += 7;
		if ((cur & 0x80) == 0)
			break;
	}
	value = (value << (64 - shift)) >> (64 - shift);
	return value;
}

uint64_t readLEB128(const uint8_t*& current, const uint8_t* end)
{
	uint64_t result = 0;
	int bit = 0;
	do
	{
		if (current >= end)
			return -1;

		uint64_t slice = *current & 0x7f;

		if (bit > 63)
			return -1;
		result |= (slice << bit);
		bit += 7;
	} while (*current++ & 0x80);
	return result;
}


uint64_t readValidULEB128(const uint8_t*& current, const uint8_t* end)
{
	uint64_t value = readLEB128(current, end);
	if ((int64_t)value == -1)
		throw ReadException();
	return value;
}

void ApplySymbol(Ref<BinaryView> view, Ref<ImportLibrary> importLib, Ref<Symbol> symbol, Ref<Type> type)
{
	auto symbolAddress = symbol->GetAddress();
	auto symbolName = symbol->GetFullName();

	// Sometimes the symbol will be duplicated, so lets not do this work again.
	if (view->GetSymbolByAddress(symbolAddress))
		return;

	// Define the symbol!
	view->DefineAutoSymbol(symbol);

	// Try and pull a type from an import library to apply at the symbol location.
	// The import library type will take precedence over the passed in type.
	Ref<Type> selectedType = type;
	if (importLib)
		selectedType = view->ImportObjectFromLibrary(importLib, {symbolName});

	Ref<Function> func = nullptr;
	if (symbol->GetType() == FunctionSymbol)
	{
		Ref<Platform> targetPlatform = view->GetDefaultPlatform();
		// Make sure to check for already added function from the function table.
		// Unless we have retrieved a type here we don't need to make a new function.
		func = view->GetAnalysisFunction(targetPlatform, symbolAddress);
		if (!func || selectedType != nullptr)
			func = view->AddFunctionForAnalysis(targetPlatform, symbolAddress, false, selectedType);
		// The above function might be overwritten so we also want to apply the type here.
		if (func && selectedType != nullptr)
			func->ApplyAutoDiscoveredType(selectedType);
	}
	else
	{
		// Other symbol types can just use this, they don't need to worry about linear sweep removing them.
		view->DefineAutoSymbolAndVariableOrFunction(view->GetDefaultPlatform(), symbol, selectedType);
	}

	if (func)
	{
		// objective c type adjustment stuff.
		if (symbolName == "_objc_msgSend")
		{
			func->SetHasVariableArguments(false);
		}
		else if (symbolName.find("_objc_retain_x") != std::string::npos
			|| symbolName.find("_objc_release_x") != std::string::npos)
		{
			auto x = symbolName.rfind('x');
			auto num = symbolName.substr(x + 1);

			std::vector<FunctionParameter> callTypeParams;
			auto cc = view->GetDefaultArchitecture()->GetCallingConventionByName("apple-arm64-objc-fast-arc-" + num);

			if (auto idType = view->GetTypeByName({"id"}))
			{
				callTypeParams.emplace_back("obj", idType, DefaultLocationSource, Variable());
				auto funcType = Type::FunctionType(idType, cc, callTypeParams);
				func->SetUserType(funcType);
			}
			else
			{
				LogWarnF("Failed to find id type for {:#x}, objective-c processor not ran?", func->GetStart());
			}
		}
	}
}

std::string BaseFileName(const std::string& path)
{
	auto lastSlashPos = path.find_last_of("/\\");
	if (lastSlashPos != std::string::npos)
		return path.substr(lastSlashPos + 1);
	return path;
}

bool IsSameFolderForFile(Ref<ProjectFile> a, Ref<ProjectFile> b)
{
	if (!a && !b)
		return true;
	if (a && b)
		return IsSameFolder(a->GetFolder(), b->GetFolder());
	return false;
}

bool IsSameFolder(Ref<ProjectFolder> a, Ref<ProjectFolder> b)
{
	if (!a && !b)
		return true;
	if (a && b)
		return a->GetId() == b->GetId();
	return false;
}

namespace {

// Protection combinations used in XNU. Named to match the conventions in arm_vm_init.c
constexpr uint32_t PROT_RNX  = SegmentReadable | SegmentContainsData | SegmentDenyWrite | SegmentDenyExecute;
constexpr uint32_t PROT_ROX  = SegmentReadable | SegmentExecutable | SegmentContainsCode | SegmentDenyWrite;
constexpr uint32_t PROT_RWNX = SegmentReadable | SegmentWritable | SegmentContainsData | SegmentDenyExecute;

struct XNUSegmentProtection {
	std::string_view name;
	uint32_t protection;
};

// Protections taken from arm_vm_prot_init at
// https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/osfmk/arm64/arm_vm_init.c
constexpr std::array<XNUSegmentProtection, 22> s_initialSegmentProtections = {{
	// Core XNU Kernel Segments
	{"__TEXT",           PROT_RNX},
	{"__TEXT_EXEC",      PROT_ROX},
	{"__DATA_CONST",     PROT_RWNX},
	{"__DATA",           PROT_RWNX},
	{"__HIB",            PROT_RWNX},
	{"__BOOTDATA",       PROT_RWNX},
	{"__KLD",            PROT_ROX},
	{"__KLDDATA",        PROT_RNX},
	{"__LINKEDIT",       PROT_RWNX},
	{"__LAST",           PROT_ROX},
	{"__LASTDATA_CONST", PROT_RWNX},

	// Prelinked Kext Segments
	{"__PRELINK_TEXT",   PROT_RWNX},
	{"__PLK_DATA_CONST", PROT_RWNX},
	{"__PLK_TEXT_EXEC",  PROT_ROX},
	{"__PRELINK_DATA",   PROT_RWNX},
	{"__PLK_LINKEDIT",   PROT_RWNX},
	{"__PRELINK_INFO",   PROT_RWNX},
	{"__PLK_LLVM_COV",   PROT_RWNX},

	// PPL (Page Protection Layer) Segments
	{"__PPLTEXT",        PROT_ROX},
	{"__PPLTRAMP",       PROT_ROX},
	{"__PPLDATA_CONST",  PROT_RNX},
	{"__PPLDATA",        PROT_RWNX},
}};

std::string FormatSegmentFlags(uint32_t flags)
{
	std::string perms;
	perms += (flags & SegmentReadable) ? 'R' : '-';
	perms += (flags & SegmentWritable) ? 'W' : '-';
	perms += (flags & SegmentExecutable) ? 'X' : '-';

	std::string type;
	if (flags & SegmentContainsCode)
		type = " [CODE]";
	else if (flags & SegmentContainsData)
		type = " [DATA]";

	std::string denies;
	if (flags & SegmentDenyWrite)
		denies += 'W';
	if (flags & SegmentDenyExecute)
		denies += 'X';
	if (!denies.empty())
		denies = fmt::format(" (deny:{})", denies);

	return fmt::format("{}{}{}", perms, type, denies);
}

// XNU maps certain segments with specific protections regardless of what is in the load command.
uint32_t SegmentFlagsForKnownXNUSegment(std::string_view segmentName)
{
	for (const auto& entry : s_initialSegmentProtections)
	{
		if (segmentName == entry.name)
			return entry.protection;
	}
	return 0;
}

uint32_t SegmentFlagsFromMachOProtections(int initProt, int maxProt)
{
	uint32_t flags = 0;
	if (initProt & MACHO_VM_PROT_READ)
		flags |= SegmentReadable;
	if (initProt & MACHO_VM_PROT_WRITE)
		flags |= SegmentWritable;
	if (initProt & MACHO_VM_PROT_EXECUTE)
		flags |= SegmentExecutable;
	if ((initProt & MACHO_VM_PROT_WRITE) == 0 && (maxProt & MACHO_VM_PROT_WRITE) == 0)
		flags |= SegmentDenyWrite;
	if ((initProt & MACHO_VM_PROT_EXECUTE) == 0 && (maxProt & MACHO_VM_PROT_EXECUTE) == 0)
		flags |= SegmentDenyExecute;
	return static_cast<BNSegmentFlag>(flags);
}

} // unnamed namespace

uint32_t SegmentFlagsForSegment(const segment_command_64& segment)
{
	std::string_view segmentName(segment.segname, std::find(segment.segname, std::end(segment.segname), '\0'));
	uint32_t flagsFromLoadCommand = SegmentFlagsFromMachOProtections(segment.initprot, segment.maxprot);
	if (uint32_t flagsFromKnownXNUSegment = SegmentFlagsForKnownXNUSegment(segmentName))
	{
		constexpr int MASK = ~(SegmentContainsData | SegmentContainsCode);
		if ((flagsFromKnownXNUSegment & MASK) != (flagsFromLoadCommand & MASK))
			LogDebugF("Overriding segment protections from load command ({}) with known segment protections {} for segment {} ({:#x} - {:#x})",
				FormatSegmentFlags(flagsFromLoadCommand), FormatSegmentFlags(flagsFromKnownXNUSegment), segmentName,
				segment.vmaddr, segment.vmaddr + segment.vmsize);
		return flagsFromKnownXNUSegment;
	}

	return flagsFromLoadCommand;
}

uint32_t SectionSemanticsForSection(const section_64& section)
{
	std::string_view segmentName(section.segname, std::find(section.segname, std::end(section.segname), '\0'));
	int flags = SegmentFlagsForKnownXNUSegment(segmentName);
	if (!flags)
		return 0;

	if (flags & SegmentExecutable)
	  return ReadOnlyCodeSectionSemantics;

	if (flags & SegmentWritable)
	  return ReadWriteDataSectionSemantics;

	return ReadOnlyDataSectionSemantics;
}
