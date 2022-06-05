#include "typeparser.h"
#include "settings.hpp"
#include "platform.hpp"
#include "typeparser.hpp"
#include "type.hpp"

using namespace BinaryNinja;
using namespace std;

TypeAndId::TypeAndId(const std::string& id, const Ref<Type>& type)
	: id(id), type(type)
{}


TypeParser::TypeParser(const string& name)
	: m_nameForRegister(name)
{}


TypeParser::TypeParser(BNTypeParser* parser)
{
	m_object = parser;
}


ParsedType::ParsedType(const std::string& name, const Ref<Type>& type, bool isUser)
	: name(name), type(type), isUser(isUser)
{}


ParsedType::ParsedType(const QualifiedName& name, const Ref<Type>& type, bool isUser)
	: name(name), type(type), isUser(isUser)
{}


bool ParsedType::operator<(const ParsedType& other) const
{
	if (isUser != other.isUser)
		return isUser;
	return name < other.name;
}


vector<Ref<TypeParser>> TypeParser::GetList()
{
	size_t count;
	BNTypeParser** list = BNGetTypeParserList(&count);
	vector<Ref<TypeParser>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreTypeParser(list[i]));
	BNFreeTypeParserList(list);
	return result;
}


Ref<TypeParser> TypeParser::GetByName(const string& name)
{
	BNTypeParser* result = BNGetTypeParserByName(name.c_str());
	if (!result)
		return nullptr;
	return new CoreTypeParser(result);
}


Ref<TypeParser> TypeParser::GetDefault()
{
	string name = Settings::Instance()->Get<string>("analysis.types.parserName");
	return GetByName(name);
}


void TypeParser::Register(TypeParser* parser)
{
	BNTypeParserCallbacks cb;
	cb.context = parser;
	cb.preprocessSource = PreprocessSourceCallback;
	cb.parseTypesFromSource = ParseTypesFromSourceCallback;
	cb.parseTypeString = ParseTypeStringCallback;
	cb.freeString = FreeStringCallback;
	cb.freeResult = FreeResultCallback;
	cb.freeErrorList = FreeErrorListCallback;
	parser->m_object = BNRegisterTypeParser(parser->m_nameForRegister.c_str(), &cb);
}


bool TypeParser::PreprocessSourceCallback(void* ctxt,
	const char* source, const char* fileName, BNPlatform* platform,
	const BNQualifiedNameTypeAndId* existingTypes, size_t existingTypeCount,
	const char* const* options, size_t optionCount,
	const char* const* includeDirs, size_t includeDirCount,
	char** output, BNTypeParserError** errors, size_t* errorCount
)
{
	TypeParser* parser = (TypeParser*)ctxt;

	map<QualifiedName, TypeAndId> existingTypesCpp;
	for (size_t i = 0; i < existingTypeCount; i ++)
	{
		QualifiedName qname = QualifiedName::FromAPIObject(&existingTypes[i].name);
		TypeAndId type = {
			existingTypes[i].id,
			new Type(existingTypes[i].type),
		};
		existingTypesCpp.insert({qname, type});
	}

	vector<string> optionsCpp;
	for (size_t i = 0; i < optionCount; i ++)
	{
		optionsCpp.push_back(options[i]);
	}

	vector<string> includeDirsCpp;
	for (size_t i = 0; i < includeDirCount; i ++)
	{
		includeDirsCpp.push_back(includeDirs[i]);
	}

	std::string outputCpp;
	vector<TypeParserError> errorsCpp;
	bool success = parser->PreprocessSource(source, fileName, new Platform(platform),
		existingTypesCpp, optionsCpp, includeDirsCpp, outputCpp, errorsCpp);

	if (success)
	{
		*output = BNAllocString(outputCpp.c_str());
	}
	else
	{
		*output = nullptr;
	}

	*errorCount = errorsCpp.size();
	*errors = new BNTypeParserError[errorsCpp.size()];
	for (size_t i = 0; i < errorsCpp.size(); ++i)
	{
		(*errors)[i].severity = errorsCpp[i].severity;
		(*errors)[i].message = BNAllocString(errorsCpp[i].message.c_str());
		(*errors)[i].fileName = BNAllocString(errorsCpp[i].fileName.c_str());
		(*errors)[i].line = errorsCpp[i].line;
		(*errors)[i].column = errorsCpp[i].column;
	}

	return success;
}


bool TypeParser::ParseTypesFromSourceCallback(void* ctxt,
	const char* source, const char* fileName, BNPlatform* platform,
	const BNQualifiedNameTypeAndId* existingTypes, size_t existingTypeCount,
	const char* const* options, size_t optionCount,
	const char* const* includeDirs, size_t includeDirCount,
	const char* autoTypeSource, BNTypeParserResult* result,
	BNTypeParserError** errors, size_t* errorCount
)
{
	TypeParser* parser = (TypeParser*)ctxt;

	map<QualifiedName, TypeAndId> existingTypesCpp;
	for (size_t i = 0; i < existingTypeCount; i ++)
	{
		QualifiedName qname = QualifiedName::FromAPIObject(&existingTypes[i].name);
		TypeAndId type = {
			existingTypes[i].id,
			new Type(existingTypes[i].type),
		};
		existingTypesCpp.insert({qname, type});
	}

	vector<string> optionsCpp;
	for (size_t i = 0; i < optionCount; i ++)
	{
		optionsCpp.push_back(options[i]);
	}

	vector<string> includeDirsCpp;
	for (size_t i = 0; i < includeDirCount; i ++)
	{
		includeDirsCpp.push_back(includeDirs[i]);
	}

	TypeParserResult resultCpp;
	vector<TypeParserError> errorsCpp;
	bool success = parser->ParseTypesFromSource(source, fileName, new Platform(platform),
		existingTypesCpp, optionsCpp, includeDirsCpp, autoTypeSource, resultCpp, errorsCpp);

	result->typeCount = resultCpp.types.size();
	result->variableCount = resultCpp.variables.size();
	result->functionCount = resultCpp.functions.size();
	result->types = new BNParsedType[resultCpp.types.size()];
	result->variables = new BNParsedType[resultCpp.variables.size()];
	result->functions = new BNParsedType[resultCpp.functions.size()];

	size_t n = 0;
	for (auto& i : resultCpp.types)
	{
		result->types[n].name = i.name.GetAPIObject();
		result->types[n].type = BNNewTypeReference(i.type->GetObject());
		result->types[n].isUser = i.isUser;
		n++;
	}

	n = 0;
	for (auto& i : resultCpp.variables)
	{
		result->variables[n].name = i.name.GetAPIObject();
		result->variables[n].type = BNNewTypeReference(i.type->GetObject());
		result->variables[n].isUser = i.isUser;
		n++;
	}

	n = 0;
	for (auto& i : resultCpp.functions)
	{
		result->functions[n].name = i.name.GetAPIObject();
		result->functions[n].type = BNNewTypeReference(i.type->GetObject());
		result->functions[n].isUser = i.isUser;
		n++;
	}

	*errorCount = errorsCpp.size();
	*errors = new BNTypeParserError[errorsCpp.size()];
	for (size_t i = 0; i < errorsCpp.size(); ++i)
	{
		(*errors)[i].severity = errorsCpp[i].severity;
		(*errors)[i].message = BNAllocString(errorsCpp[i].message.c_str());
		(*errors)[i].fileName = BNAllocString(errorsCpp[i].fileName.c_str());
		(*errors)[i].line = errorsCpp[i].line;
		(*errors)[i].column = errorsCpp[i].column;
	}

	return success;
}


bool TypeParser::ParseTypeStringCallback(void* ctxt,
	const char* source, BNPlatform* platform,
	const BNQualifiedNameTypeAndId* existingTypes, size_t existingTypeCount,
	BNQualifiedNameAndType* result,
	BNTypeParserError** errors, size_t* errorCount
)
{
	TypeParser* parser = (TypeParser*)ctxt;

	map<QualifiedName, TypeAndId> existingTypesCpp;
	for (size_t i = 0; i < existingTypeCount; i ++)
	{
		QualifiedName qname = QualifiedName::FromAPIObject(&existingTypes[i].name);
		TypeAndId type = {
			existingTypes[i].id,
			new Type(existingTypes[i].type),
		};
		existingTypesCpp.insert({qname, type});
	}

	QualifiedNameAndType resultCpp;
	vector<TypeParserError> errorsCpp;
	bool success = parser->ParseTypeString(source, new Platform(platform), existingTypesCpp,
		resultCpp, errorsCpp);

	result->name = resultCpp.name.GetAPIObject();
	result->type = BNNewTypeReference(resultCpp.type->GetObject());

	*errorCount = errorsCpp.size();
	*errors = new BNTypeParserError[errorsCpp.size()];
	for (size_t i = 0; i < errorsCpp.size(); ++i)
	{
		(*errors)[i].severity = errorsCpp[i].severity;
		(*errors)[i].message = BNAllocString(errorsCpp[i].message.c_str());
		(*errors)[i].fileName = BNAllocString(errorsCpp[i].fileName.c_str());
		(*errors)[i].line = errorsCpp[i].line;
		(*errors)[i].column = errorsCpp[i].column;
	}

	return success;
}


void TypeParser::FreeStringCallback(void* ctxt, char* result)
{
	BNFreeString(result);
}


void TypeParser::FreeResultCallback(void* ctxt, BNTypeParserResult* result)
{
	for (size_t i = 0; i < result->typeCount; i++)
	{
		QualifiedName::FreeAPIObject(&result->types[i].name);
		BNFreeType(result->types[i].type);
	}
	for (size_t i = 0; i < result->variableCount; i++)
	{
		QualifiedName::FreeAPIObject(&result->variables[i].name);
		BNFreeType(result->variables[i].type);
	}
	for (size_t i = 0; i < result->functionCount; i++)
	{
		QualifiedName::FreeAPIObject(&result->functions[i].name);
		BNFreeType(result->functions[i].type);
	}
	delete[] result->types;
	delete[] result->variables;
	delete[] result->functions;
}


void TypeParser::FreeErrorListCallback(void* ctxt, BNTypeParserError* errors, size_t errorCount)
{
	for (size_t i = 0; i < errorCount; i ++)
	{
		BNFreeString(errors[i].message);
		BNFreeString(errors[i].fileName);
	}
	delete[] errors;
}


CoreTypeParser::CoreTypeParser(BNTypeParser* parser): TypeParser(parser)
{

}


bool CoreTypeParser::PreprocessSource(const std::string& source, const std::string& fileName,
	Ref<Platform> platform, const std::map<QualifiedName, TypeAndId>& existingTypes,
	const std::vector<std::string>& options, const std::vector<std::string>& includeDirs,
	std::string& output, std::vector<TypeParserError>& errors)
{
	const char** apiOptions = new const char*[options.size()];
	for (size_t i = 0; i < options.size(); ++i)
	{
		apiOptions[i] = options[i].c_str();
	}
	const char** apiIncludeDirs = new const char*[includeDirs.size()];
	for (size_t i = 0; i < includeDirs.size(); ++i)
	{
		apiIncludeDirs[i] = includeDirs[i].c_str();
	}

	BNQualifiedNameTypeAndId* apiExistingTypes = new BNQualifiedNameTypeAndId[existingTypes.size()];
	size_t i = 0;
	for (const auto& pair: existingTypes)
	{
		apiExistingTypes[i].name = pair.first.GetAPIObject();
		apiExistingTypes[i].id = BNAllocString(pair.second.id.c_str());
		apiExistingTypes[i].type = pair.second.type->GetObject();
		i++;
	}

	char* apiOutput;
	BNTypeParserError* apiErrors;
	size_t errorCount;

	auto success = BNTypeParserPreprocessSource(m_object, source.c_str(), fileName.c_str(),
		platform->GetObject(), apiExistingTypes, existingTypes.size(),
		apiOptions, options.size(), apiIncludeDirs, includeDirs.size(), &apiOutput,
		&apiErrors, &errorCount);

	delete [] apiOptions;
	delete [] apiIncludeDirs;

	for (size_t j = 0; j < existingTypes.size(); j ++)
	{
		QualifiedName::FreeAPIObject(&apiExistingTypes[j].name);
		BNFreeString(apiExistingTypes[j].id);
	}
	delete [] apiExistingTypes;

	for (size_t j = 0; j < errorCount; j ++)
	{
		TypeParserError error;
		error.severity =  apiErrors[j].severity,
		error.message =  apiErrors[j].message,
		error.fileName =  apiErrors[j].fileName,
		error.line =  apiErrors[j].line,
		error.column =  apiErrors[j].column,
		errors.push_back(error);
	}
	BNFreeTypeParserErrors(apiErrors, errorCount);

	if (!success)
	{
		return false;
	}

	output = apiOutput;
	BNFreeString(apiOutput);
	return true;
}


bool CoreTypeParser::ParseTypesFromSource(const std::string& source, const std::string& fileName,
	Ref<Platform> platform, const std::map<QualifiedName, TypeAndId>& existingTypes,
	const std::vector<std::string>& options, const std::vector<std::string>& includeDirs,
	const std::string& autoTypeSource, TypeParserResult& result, std::vector<TypeParserError>& errors)
{
	const char** apiOptions = new const char*[options.size()];
	for (size_t i = 0; i < options.size(); ++i)
	{
		apiOptions[i] = options[i].c_str();
	}
	const char** apiIncludeDirs = new const char*[includeDirs.size()];
	for (size_t i = 0; i < includeDirs.size(); ++i)
	{
		apiIncludeDirs[i] = includeDirs[i].c_str();
	}

	BNQualifiedNameTypeAndId* apiExistingTypes = new BNQualifiedNameTypeAndId[existingTypes.size()];
	size_t i = 0;
	for (const auto& pair: existingTypes)
	{
		apiExistingTypes[i].name = pair.first.GetAPIObject();
		apiExistingTypes[i].id = BNAllocString(pair.second.id.c_str());
		apiExistingTypes[i].type = pair.second.type->GetObject();
		i++;
	}

	BNTypeParserResult apiResult;
	BNTypeParserError* apiErrors;
	size_t errorCount;

	auto success = BNTypeParserParseTypesFromSource(m_object, source.c_str(), fileName.c_str(),
		platform->GetObject(), apiExistingTypes, existingTypes.size(),
		apiOptions, options.size(), apiIncludeDirs, includeDirs.size(), autoTypeSource.c_str(), &apiResult,
		&apiErrors, &errorCount);

	delete [] apiOptions;
	delete [] apiIncludeDirs;

	for (size_t j = 0; j < existingTypes.size(); j ++)
	{
		QualifiedName::FreeAPIObject(&apiExistingTypes[j].name);
		BNFreeString(apiExistingTypes[j].id);
	}
	delete [] apiExistingTypes;

	for (size_t j = 0; j < errorCount; j ++)
	{
		TypeParserError error;
		error.severity =  apiErrors[j].severity,
		error.message =  apiErrors[j].message,
		error.fileName =  apiErrors[j].fileName,
		error.line =  apiErrors[j].line,
		error.column =  apiErrors[j].column,
		errors.push_back(error);
	}
	BNFreeTypeParserErrors(apiErrors, errorCount);

	if (!success)
	{
		return false;
	}

	result.types.clear();
	for (size_t j = 0; j < apiResult.typeCount; ++j)
	{
		result.types.push_back({
			QualifiedName::FromAPIObject(&apiResult.types[j].name),
			new Type(BNNewTypeReference(apiResult.types[j].type)),
			apiResult.types[j].isUser
		});
	}

	result.variables.clear();
	for (size_t j = 0; j < apiResult.variableCount; ++j)
	{
		result.variables.push_back({
			QualifiedName::FromAPIObject(&apiResult.variables[j].name),
			new Type(BNNewTypeReference(apiResult.variables[j].type)),
			apiResult.types[j].isUser
		});
	}

	result.functions.clear();
	for (size_t j = 0; j < apiResult.functionCount; ++j)
	{
		result.functions.push_back({
			QualifiedName::FromAPIObject(&apiResult.functions[j].name),
			new Type(BNNewTypeReference(apiResult.functions[j].type)),
			apiResult.types[j].isUser
		});
	}

	BNFreeTypeParserResult(&apiResult);
	return true;
}


bool CoreTypeParser::ParseTypeString(const std::string& source, Ref<Platform> platform,
	const std::map<QualifiedName, TypeAndId>& existingTypes,
	QualifiedNameAndType& result, std::vector<TypeParserError>& errors)
{
	BNQualifiedNameTypeAndId* apiExistingTypes = new BNQualifiedNameTypeAndId[existingTypes.size()];
	size_t i = 0;
	for (const auto& pair: existingTypes)
	{
		apiExistingTypes[i].name = pair.first.GetAPIObject();
		apiExistingTypes[i].id = BNAllocString(pair.second.id.c_str());
		apiExistingTypes[i].type = pair.second.type->GetObject();
	}

	BNQualifiedNameAndType apiResult;
	BNTypeParserError* apiErrors;
	size_t errorCount;

	auto success = BNTypeParserParseTypeString(m_object, source.c_str(), platform->GetObject(),
		apiExistingTypes, existingTypes.size(), &apiResult,
		&apiErrors, &errorCount);

	for (size_t j = 0; j < existingTypes.size(); j ++)
	{
		QualifiedName::FreeAPIObject(&apiExistingTypes[j].name);
		BNFreeString(apiExistingTypes[j].id);
	}
	delete [] apiExistingTypes;

	for (size_t j = 0; j < errorCount; j ++)
	{
		TypeParserError error;
		error.severity =  apiErrors[j].severity,
		error.message =  apiErrors[j].message,
		error.fileName =  apiErrors[j].fileName,
		error.line =  apiErrors[j].line,
		error.column =  apiErrors[j].column,
		errors.push_back(error);
	}
	BNFreeTypeParserErrors(apiErrors, errorCount);

	if (!success)
	{
		return false;
	}

	result.name = QualifiedName::FromAPIObject(&apiResult.name);
	result.type = new Type(BNNewTypeReference(apiResult.type));
	BNFreeQualifiedNameAndType(&apiResult);

	return true;
}
