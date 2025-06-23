#include "objctypes.h"
#include "binaryninjaapi.h"

using namespace BinaryNinja;

namespace {

bool IsPointerToObjCObject(const Ref<Type>& type)
{
	if (!type || type->GetClass() != PointerTypeClass)
		return false;

	auto childType = type->GetChildType();
	if (!childType || childType->GetClass() != NamedTypeReferenceClass)
		return false;

	auto namedType = childType->GetNamedTypeReference();
	return namedType && namedType->GetName().GetString() == "objc_object";
}

}  // unnamed namespace

PseudoObjCTypePrinter::PseudoObjCTypePrinter() : TypePrinter("Objective-C") {}

std::vector<InstructionTextToken> PseudoObjCTypePrinter::GetTypeTokensBeforeName(
	Ref<Type> type, Ref<Platform> platform, uint8_t baseConfidence, Ref<Type> parentType, BNTokenEscapingType escaping)
{
	// It is idiomatic in Objective-C to use `id` rather than `objc_object*`.
	if (IsPointerToObjCObject(type))
		return {InstructionTextToken {baseConfidence, TypeNameToken, "id"}};

	return TypePrinter::GetDefault()->GetTypeTokensBeforeName(type, platform, baseConfidence, parentType, escaping);
}

std::vector<InstructionTextToken> PseudoObjCTypePrinter::GetTypeTokensAfterName(
	Ref<Type> type, Ref<Platform> platform, uint8_t baseConfidence, Ref<Type> parentType, BNTokenEscapingType escaping)
{
	return TypePrinter::GetDefault()->GetTypeTokensAfterName(type, platform, baseConfidence, parentType, escaping);
}

std::vector<TypeDefinitionLine> PseudoObjCTypePrinter::GetTypeLines(Ref<Type> type, const TypeContainer& types,
	const QualifiedName& name, int paddingCols, bool collapsed, BNTokenEscapingType escaping)
{
	return TypePrinter::GetDefault()->GetTypeLines(type, types, name, paddingCols, collapsed, escaping);
}
