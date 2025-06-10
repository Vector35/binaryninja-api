#include "Utility.h"
#include "binaryninjaapi.h"
#include "view/macho/machoview.h"

using namespace BinaryNinja;

BNSegmentFlag SegmentFlagsFromMachOProtections(int initProt, int maxProt)
{
	uint32_t flags = 0;
	if (initProt & MACHO_VM_PROT_READ)
		flags |= SegmentReadable;
	if (initProt & MACHO_VM_PROT_WRITE)
		flags |= SegmentWritable;
	if (initProt & MACHO_VM_PROT_EXECUTE)
		flags |= SegmentExecutable;
	if (((initProt & MACHO_VM_PROT_WRITE) == 0) && ((maxProt & MACHO_VM_PROT_WRITE) == 0))
		flags |= SegmentDenyWrite;
	if (((initProt & MACHO_VM_PROT_EXECUTE) == 0) && ((maxProt & MACHO_VM_PROT_EXECUTE) == 0))
		flags |= SegmentDenyExecute;
	return static_cast<BNSegmentFlag>(flags);
}

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

void ApplySymbol(Ref<BinaryView> view, Ref<TypeLibrary> typeLib, Ref<Symbol> symbol, Ref<Type> type)
{
	auto symbolAddress = symbol->GetAddress();
	auto symbolName = symbol->GetFullName();

	// Sometimes the symbol will be duplicated, so lets not do this work again.
	if (view->GetSymbolByAddress(symbolAddress))
		return;

	// Define the symbol!
	view->DefineAutoSymbol(symbol);

	// Try and pull a type from a type library to apply at the symbol location.
	// The type library type will take precedence over the passed in type.
	Ref<Type> selectedType = type;
	if (typeLib)
		selectedType = view->ImportTypeLibraryObject(typeLib, {symbolName});

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
				callTypeParams.emplace_back("obj", idType, true, Variable());
				auto funcType = Type::FunctionType(idType, cc, callTypeParams);
				func->SetUserType(funcType);
			}
			else
			{
				LogWarn("Failed to find id type for %llx, objective-c processor not ran?", func->GetStart());
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
