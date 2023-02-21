#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;

TypePrinter::TypePrinter(const std::string& name): m_nameForRegister(name)
{

}


TypePrinter::TypePrinter(BNTypePrinter* printer)
{
	m_object = printer;
}


bool TypePrinter::GetTypeTokensCallback(void* ctxt, BNType* type, BNPlatform* platform,
	BNQualifiedName* name, uint8_t baseConfidence, BNTokenEscapingType escaping,
	BNInstructionTextToken** result, size_t* resultCount)
{
	TypePrinter* printer = (TypePrinter*)ctxt;
	vector<InstructionTextToken> tokens = printer->GetTypeTokens(
		new Type(BNNewTypeReference(type)), platform ? new Platform(BNNewPlatformReference(platform)) : nullptr,
		QualifiedName::FromAPIObject(name), baseConfidence, escaping);

	*resultCount = tokens.size();
	*result = InstructionTextToken::CreateInstructionTextTokenList(tokens);
	return true;
}


bool TypePrinter::GetTypeTokensBeforeNameCallback(void* ctxt, BNType* type,
	BNPlatform* platform, uint8_t baseConfidence, BNType* parentType,
	BNTokenEscapingType escaping, BNInstructionTextToken** result,
	size_t* resultCount)
{
	TypePrinter* printer = (TypePrinter*)ctxt;
	vector<InstructionTextToken> tokens = printer->GetTypeTokensBeforeName(
		new Type(BNNewTypeReference(type)), platform ? new Platform(BNNewPlatformReference(platform)) : nullptr,
		baseConfidence, parentType ? new Type(BNNewTypeReference(parentType)) : nullptr, escaping);

	*resultCount = tokens.size();
	*result = InstructionTextToken::CreateInstructionTextTokenList(tokens);
	return true;
}


bool TypePrinter::GetTypeTokensAfterNameCallback(void* ctxt, BNType* type,
	BNPlatform* platform, uint8_t baseConfidence, BNType* parentType,
	BNTokenEscapingType escaping, BNInstructionTextToken** result,
	size_t* resultCount)
{
	TypePrinter* printer = (TypePrinter*)ctxt;
	vector<InstructionTextToken> tokens = printer->GetTypeTokensAfterName(
		new Type(BNNewTypeReference(type)), platform ? new Platform(BNNewPlatformReference(platform)) : nullptr,
		baseConfidence, parentType ? new Type(BNNewTypeReference(parentType)) : nullptr, escaping);

	*resultCount = tokens.size();
	*result = InstructionTextToken::CreateInstructionTextTokenList(tokens);
	return true;
}


bool TypePrinter::GetTypeStringCallback(void* ctxt, BNType* type, BNPlatform* platform,
	BNQualifiedName* name, BNTokenEscapingType escaping, char** result)
{
	TypePrinter* printer = (TypePrinter*)ctxt;
	string text = printer->GetTypeString(
		new Type(BNNewTypeReference(type)), platform ? new Platform(BNNewPlatformReference(platform)) : nullptr,
		QualifiedName::FromAPIObject(name), escaping);

	*result = BNAllocString(text.c_str());
	return true;
}


bool TypePrinter::GetTypeStringBeforeNameCallback(void* ctxt, BNType* type,
	BNPlatform* platform, BNTokenEscapingType escaping, char** result)
{
	TypePrinter* printer = (TypePrinter*)ctxt;
	string text = printer->GetTypeStringBeforeName(
		new Type(BNNewTypeReference(type)), platform ? new Platform(BNNewPlatformReference(platform)) : nullptr,
		escaping);

	*result = BNAllocString(text.c_str());
	return true;
}


bool TypePrinter::GetTypeStringAfterNameCallback(void* ctxt, BNType* type,
	BNPlatform* platform, BNTokenEscapingType escaping, char** result)
{
	TypePrinter* printer = (TypePrinter*)ctxt;
	string text = printer->GetTypeStringAfterName(
		new Type(BNNewTypeReference(type)), platform ? new Platform(BNNewPlatformReference(platform)) : nullptr,
		escaping);

	*result = BNAllocString(text.c_str());
	return true;
}


bool TypePrinter::GetTypeLinesCallback(void* ctxt, BNType* type, BNTypeContainer* types,
	BNQualifiedName* name, int lineWidth, bool collapsed,
	BNTokenEscapingType escaping, BNTypeDefinitionLine** result, size_t* resultCount)
{
	TypePrinter* printer = (TypePrinter*)ctxt;
	vector<TypeDefinitionLine> lines = printer->GetTypeLines(
		new Type(BNNewTypeReference(type)), TypeContainer(types),
		QualifiedName::FromAPIObject(name), lineWidth, collapsed, escaping);

	*resultCount = lines.size();
	*result = TypeDefinitionLine::CreateTypeDefinitionLineList(lines);
	return true;
}


bool TypePrinter::PrintAllTypesCallback(void* ctxt, BNQualifiedName* names, BNType** types, size_t typeCount,
	BNBinaryView* data, int lineWidth, BNTokenEscapingType escaping, char** result)
{
	TypePrinter* printer = (TypePrinter*)ctxt;
	vector<pair<QualifiedName, Ref<Type>>> apiTypes;
	for (size_t i = 0; i < typeCount; ++i)
	{
		apiTypes.push_back({QualifiedName::FromAPIObject(&names[i]), new Type(types[i])});
	}

	string resultStr = printer->PrintAllTypes(apiTypes, new BinaryView(data), lineWidth, escaping);
	*result = BNAllocString(resultStr.c_str());
	return true;
}


void TypePrinter::FreeTokensCallback(void* ctxt, BNInstructionTextToken* tokens, size_t count)
{
	InstructionTextToken::FreeInstructionTextTokenList(tokens, count);
}


void TypePrinter::FreeStringCallback(void* ctxt, char* string)
{
	BNFreeString(string);
}


void TypePrinter::FreeLinesCallback(void* ctxt, BNTypeDefinitionLine* lines, size_t count)
{
	TypeDefinitionLine::FreeTypeDefinitionLineList(lines, count);
}


void TypePrinter::Register(TypePrinter* printer)
{
	BNTypePrinterCallbacks cb;
	cb.context = printer;
	cb.getTypeTokens = GetTypeTokensCallback;
	cb.getTypeTokensBeforeName = GetTypeTokensBeforeNameCallback;
	cb.getTypeTokensAfterName = GetTypeTokensAfterNameCallback;
	cb.getTypeString = GetTypeStringCallback;
	cb.getTypeStringBeforeName = GetTypeStringBeforeNameCallback;
	cb.getTypeStringAfterName = GetTypeStringAfterNameCallback;
	cb.getTypeLines = GetTypeLinesCallback;
	cb.freeTokens = FreeTokensCallback;
	cb.freeString = FreeStringCallback;
	cb.freeLines = FreeLinesCallback;
	printer->m_object = BNRegisterTypePrinter(printer->m_nameForRegister.c_str(), &cb);
}


std::vector<Ref<TypePrinter>> TypePrinter::GetList()
{
	size_t count;
	BNTypePrinter** list = BNGetTypePrinterList(&count);
	vector<Ref<TypePrinter>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreTypePrinter(list[i]));
	BNFreeTypePrinterList(list);
	return result;
}


Ref<TypePrinter> TypePrinter::GetByName(const std::string& name)
{
	BNTypePrinter* result = BNGetTypePrinterByName(name.c_str());
	if (!result)
		return nullptr;
	return new CoreTypePrinter(result);
}


Ref<TypePrinter> TypePrinter::GetDefault()
{
	string name = Settings::Instance()->Get<string>("analysis.types.printerName");
	return GetByName(name);
}


std::vector<InstructionTextToken> TypePrinter::GetTypeTokens(
	Ref<Type> type,
	Ref<Platform> platform,
	const QualifiedName& name,
	uint8_t baseConfidence,
	BNTokenEscapingType escaping
)
{
	vector<InstructionTextToken> before = GetTypeTokensBeforeName(type, platform, baseConfidence, nullptr, escaping);
	vector<InstructionTextToken> after = GetTypeTokensAfterName(type, platform, baseConfidence, nullptr, escaping);
	if (before.size() > 0 && before.back().text.back() != ' ' && before.back().text.back() != '*' &&
		before.back().text.back() != '&' && after.size() > 0 && after.front().text.front() != ' ')
	{
		if (type->GetClass() != FunctionTypeClass)
			before.emplace_back(TextToken, " ");
	}
	before.insert(before.end(), after.begin(), after.end());
	return before;
}


std::string TypePrinter::GetTypeString(
	Ref<Type> type,
	Ref<Platform> platform,
	const QualifiedName& name,
	BNTokenEscapingType escaping
)
{
	const string before = GetTypeStringBeforeName(type, platform, escaping);
	const string qName = name.GetString(escaping);
	const string after = GetTypeStringAfterName(type, platform, escaping);
	if (((before.size() > 0) && (qName.size() > 0) && (before.back() != ' ') && (qName.front() != ' ')) ||
		((before.size() > 0) && (after.size() > 0) && (before.back() != ' ') && (after.front() != ' ')))
		return before + " " + qName + after;
	return before + qName + after;
}


std::string TypePrinter::GetTypeStringBeforeName(
	Ref<Type> type,
	Ref<Platform> platform,
	BNTokenEscapingType escaping
)
{
	vector<InstructionTextToken> tokens = GetTypeTokensBeforeName(type, platform, BN_FULL_CONFIDENCE, nullptr, escaping);
	string result;
	for (const auto& i : tokens)
		result += i.text;
	return result;
}


std::string TypePrinter::GetTypeStringAfterName(
	Ref<Type> type,
	Ref<Platform> platform,
	BNTokenEscapingType escaping
)
{
	vector<InstructionTextToken> tokens = GetTypeTokensAfterName(type, platform, BN_FULL_CONFIDENCE, nullptr, escaping);
	string result;
	for (const auto& i : tokens)
		result += i.text;
	return result;
}


std::string TypePrinter::PrintAllTypes(
	const std::vector<std::pair<QualifiedName, Ref<Type>>>& types,
	Ref<BinaryView> data,
	int lineWidth,
	BNTokenEscapingType escaping
)
{
	return DefaultPrintAllTypes(types, data, lineWidth, escaping);
}


std::string TypePrinter::DefaultPrintAllTypes(
	const std::vector<std::pair<QualifiedName, Ref<Type>>>& types,
	Ref<BinaryView> data,
	int lineWidth,
	BNTokenEscapingType escaping
)
{
	BNQualifiedName* apiNames = new BNQualifiedName[types.size()];
	BNType** apiTypes = new BNType*[types.size()];

	for (size_t i = 0; i < types.size(); i ++)
	{
		apiNames[i] = types[i].first.GetAPIObject();
		apiTypes[i] = types[i].second->GetObject();
	}

	char* resultStr;
	BNTypePrinterDefaultPrintAllTypes(m_object, apiNames, apiTypes, types.size(), data->GetObject(),
		lineWidth, escaping, &resultStr);

	for (size_t i = 0; i < types.size(); i ++)
	{
		QualifiedName::FreeAPIObject(&apiNames[i]);
	}
	delete[] apiTypes;
	delete[] apiNames;

	std::string result = resultStr;
	BNFreeString(resultStr);
	return result;
}


CoreTypePrinter::CoreTypePrinter(BNTypePrinter* printer): TypePrinter(printer)
{

}


std::vector<InstructionTextToken> CoreTypePrinter::GetTypeTokens(Ref<Type> type,
	Ref<Platform> platform, const QualifiedName& name,
	uint8_t baseConfidence, BNTokenEscapingType escaping)
{
	BNQualifiedName qname = name.GetAPIObject();

	BNInstructionTextToken* tokens;
	size_t tokenCount;

	bool success = BNGetTypePrinterTypeTokens(GetObject(), type->GetObject(),
		platform ? platform->GetObject() : nullptr, &qname, baseConfidence, escaping, &tokens, &tokenCount);

	QualifiedName::FreeAPIObject(&qname);
	if (!success)
		return {};

	vector<InstructionTextToken> cppTokens =
		InstructionTextToken::ConvertInstructionTextTokenList(tokens, tokenCount);
	BNFreeInstructionText(tokens, tokenCount);

	return cppTokens;
}


std::vector<InstructionTextToken> CoreTypePrinter::GetTypeTokensBeforeName(Ref<Type> type,
	Ref<Platform> platform, uint8_t baseConfidence,
	Ref<Type> parentType, BNTokenEscapingType escaping)
{
	BNInstructionTextToken* tokens;
	size_t tokenCount;

	bool success = BNGetTypePrinterTypeTokensBeforeName(GetObject(), type->GetObject(),
		platform ? platform->GetObject() : nullptr, baseConfidence,
		parentType ? parentType->GetObject() : nullptr, escaping, &tokens, &tokenCount);

	if (!success)
		return {};

	vector<InstructionTextToken> cppTokens =
		InstructionTextToken::ConvertInstructionTextTokenList(tokens, tokenCount);
	BNFreeInstructionText(tokens, tokenCount);

	return cppTokens;
}


std::vector<InstructionTextToken> CoreTypePrinter::GetTypeTokensAfterName(Ref<Type> type,
	Ref<Platform> platform, uint8_t baseConfidence,
	Ref<Type> parentType, BNTokenEscapingType escaping)
{
	BNInstructionTextToken* tokens;
	size_t tokenCount;

	bool success = BNGetTypePrinterTypeTokensAfterName(GetObject(), type->GetObject(),
		platform ? platform->GetObject() : nullptr, baseConfidence,
		parentType ? parentType->GetObject() : nullptr, escaping, &tokens, &tokenCount);

	if (!success)
		return {};

	vector<InstructionTextToken> cppTokens =
		InstructionTextToken::ConvertInstructionTextTokenList(tokens, tokenCount);
	BNFreeInstructionText(tokens, tokenCount);

	return cppTokens;
}


std::string CoreTypePrinter::GetTypeString(Ref<Type> type, Ref<Platform> platform,
	const QualifiedName& name, BNTokenEscapingType escaping)
{
	BNQualifiedName qname = name.GetAPIObject();

	char* result;
	bool success = BNGetTypePrinterTypeString(GetObject(), type->GetObject(), platform ? platform->GetObject() : nullptr, &qname, escaping, &result);

	QualifiedName::FreeAPIObject(&qname);
	if (!success)
		return {};

	string cppResult = result;
	BNFreeString(result);

	return cppResult;

}


std::string CoreTypePrinter::GetTypeStringBeforeName(Ref<Type> type, Ref<Platform> platform,
	BNTokenEscapingType escaping)
{
	char* result;
	bool success = BNGetTypePrinterTypeStringBeforeName(GetObject(), type->GetObject(), platform ? platform->GetObject() : nullptr, escaping, &result);

	if (!success)
		return {};

	string cppResult = result;
	BNFreeString(result);

	return cppResult;
}


std::string CoreTypePrinter::GetTypeStringAfterName(Ref<Type> type, Ref<Platform> platform,
	BNTokenEscapingType escaping)
{
	char* result;
	bool success = BNGetTypePrinterTypeStringAfterName(GetObject(), type->GetObject(), platform ? platform->GetObject() : nullptr, escaping, &result);

	if (!success)
		return {};

	string cppResult = result;
	BNFreeString(result);

	return cppResult;
}


std::vector<TypeDefinitionLine> CoreTypePrinter::GetTypeLines(Ref<Type> type,
	const TypeContainer& types, const QualifiedName& name, int lineWidth,
	bool collapsed, BNTokenEscapingType escaping)
{
	BNTypeDefinitionLine* lines;
	size_t lineCount;

	BNQualifiedName qname = name.GetAPIObject();

	bool success = BNGetTypePrinterTypeLines(GetObject(), type->GetObject(), types.GetObject(), &qname,
		lineWidth, collapsed, escaping, &lines, &lineCount);

	QualifiedName::FreeAPIObject(&qname);
	if (!success)
		return {};

	vector<TypeDefinitionLine> cppLines;

	for (size_t i = 0; i < lineCount; ++i)
	{
		cppLines.push_back(TypeDefinitionLine::FromAPIObject(&lines[i]));
	}
	BNFreeTypeDefinitionLineList(lines, lineCount);

	return cppLines;

}


std::string CoreTypePrinter::PrintAllTypes(
	const std::vector<std::pair<QualifiedName, Ref<Type>>>& types,
	Ref<BinaryView> data,
	int lineWidth,
	BNTokenEscapingType escaping
)
{
	BNQualifiedName* apiNames = new BNQualifiedName[types.size()];
	BNType** apiTypes = new BNType*[types.size()];

	for (size_t i = 0; i < types.size(); i ++)
	{
		apiNames[i] = types[i].first.GetAPIObject();
		apiTypes[i] = types[i].second->GetObject();
	}

	char* resultStr;
	BNTypePrinterPrintAllTypes(m_object, apiNames, apiTypes, types.size(), data->GetObject(),
		lineWidth, escaping, &resultStr);

	for (size_t i = 0; i < types.size(); i ++)
	{
		QualifiedName::FreeAPIObject(&apiNames[i]);
	}
	delete[] apiTypes;
	delete[] apiNames;

	std::string result = resultStr;
	BNFreeString(resultStr);
	return result;
}
