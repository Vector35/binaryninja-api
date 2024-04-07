#include "binaryninjaapi.h"
#include <filesystem>

using namespace BinaryNinja;
using namespace std;
namespace fs = std::filesystem;


TypeParser::TypeParser(const string& name) : m_nameForRegister(name) {}


TypeParser::TypeParser(BNTypeParser* parser)
{
	m_object = parser;
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
	return new CoreTypeParser(BNGetDefaultTypeParser());
}


void TypeParser::Register(TypeParser* parser)
{
	BNTypeParserCallbacks cb;
	cb.context = parser;
	cb.getOptionText = GetOptionTextCallback;
	cb.preprocessSource = PreprocessSourceCallback;
	cb.parseTypesFromSource = ParseTypesFromSourceCallback;
	cb.parseTypeString = ParseTypeStringCallback;
	cb.freeString = FreeStringCallback;
	cb.freeResult = FreeResultCallback;
	cb.freeErrorList = FreeErrorListCallback;
	parser->m_object = BNRegisterTypeParser(parser->m_nameForRegister.c_str(), &cb);
}


std::vector<std::string> TypeParser::ParseOptionsText(const std::string& optionsText)
{
	size_t count;
	char** options = BNParseTypeParserOptionsText(optionsText.c_str(), &count);

	std::vector<std::string> result;
	for (size_t i = 0; i < count; i++)
	{
		result.push_back(options[i]);
	}

	BNFreeStringList(options, count);
	return result;
}


std::string TypeParser::FormatParseErrors(const std::vector<TypeParserError>& errors)
{
	std::vector<BNTypeParserError> apiErrors;
	for (const auto& error: errors)
	{
		BNTypeParserError apiError;
		apiError.severity = error.severity;
		apiError.message = BNAllocString(error.message.c_str());
		apiError.fileName = BNAllocString(error.fileName.c_str());
		apiError.line = error.line;
		apiError.column = error.column;
		apiErrors.push_back(apiError);
	}

	char* string = BNFormatTypeParserParseErrors(apiErrors.data(), apiErrors.size());

	for (auto& apiError: apiErrors)
	{
		BNFreeString(apiError.message);
		BNFreeString(apiError.fileName);
	}

	return string;
}


bool TypeParser::GetOptionText(BNTypeParserOption option, std::string value, std::string& result) const
{
	// Default: Don't accept anything
	return false;
}


bool TypeParser::GetOptionTextCallback(void* ctxt, BNTypeParserOption option, const char* value,
	char** result)
{
	TypeParser* parser = (TypeParser*)ctxt;
	string resultCpp;
	if (!parser->GetOptionText(option, value, resultCpp))
	{
		return false;
	}
	*result = BNAllocString(resultCpp.c_str());
	return true;
}


bool TypeParser::PreprocessSourceCallback(void* ctxt,
	const char* source, const char* fileName, BNPlatform* platform,
	BNTypeContainer* existingTypes,
	const char* const* options, size_t optionCount,
	const char* const* includeDirs, size_t includeDirCount,
	char** output, BNTypeParserError** errors, size_t* errorCount
)
{
	TypeParser* parser = (TypeParser*)ctxt;

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
	bool success = parser->PreprocessSource(
		source,
		fileName,
		new Platform(platform),
		TypeContainer{BNDuplicateTypeContainer(existingTypes)},
		optionsCpp,
		includeDirsCpp,
		outputCpp,
		errorsCpp
	);

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
	BNTypeContainer* existingTypes,
	const char* const* options, size_t optionCount,
	const char* const* includeDirs, size_t includeDirCount,
	const char* autoTypeSource, BNTypeParserResult* result,
	BNTypeParserError** errors, size_t* errorCount
)
{
	TypeParser* parser = (TypeParser*)ctxt;

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
	bool success = parser->ParseTypesFromSource(
		source,
		fileName,
		new Platform(platform),
		TypeContainer{BNDuplicateTypeContainer(existingTypes)},
		optionsCpp,
		includeDirsCpp,
		autoTypeSource,
		resultCpp,
		errorsCpp
	);

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
	BNTypeContainer* existingTypes,
	BNQualifiedNameAndType* result,
	BNTypeParserError** errors, size_t* errorCount
)
{
	TypeParser* parser = (TypeParser*)ctxt;

	QualifiedNameAndType resultCpp;
	vector<TypeParserError> errorsCpp;
	bool success = parser->ParseTypeString(
		source,
		new Platform(platform),
		TypeContainer{BNDuplicateTypeContainer(existingTypes)},
		resultCpp,
		errorsCpp
	);

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


bool TypeParser::ParseTypesFromSourceFile(const string& fileName, Ref<Platform> platform,
	std::optional<TypeContainer> existingTypes, const vector<string>& options,
	const vector<string>& includeDirs, const string& autoTypeSource, TypeParserResult& result,
	vector<TypeParserError>& errors)
{
	if (!fs::is_regular_file(fileName))
	{
		errors.push_back(TypeParserError(FatalSeverity, string("error: argument '") + fileName + "' is not a file"));
		return false;
	}

	// Read file contents, then parse them
	FILE* fp = fopen(fileName.c_str(), "rb");
	if (!fp)
	{
		errors.push_back(TypeParserError(FatalSeverity, string("file '") + fileName + "' not found"));
		return false;
	}

	fseek(fp, 0, SEEK_END);
	long size = ftell(fp);
	if(size == -1)
	{
		errors.push_back(TypeParserError(FatalSeverity, string("error: unable to open '") + fileName));
		return false;
	}
	fseek(fp, 0, SEEK_SET);

	char* data = new char[size + 2];
	if (fread(data, 1, size, fp) != (size_t)size)
	{
		errors.push_back(TypeParserError(FatalSeverity, string("error: file '") + fileName + "' could not be read"));
		delete[] data;
		fclose(fp);
		return false;
	}
	data[size++] = '\n';
	data[size] = 0;
	fclose(fp);

	bool ok = ParseTypesFromSource(data, fileName, platform, existingTypes, options, includeDirs, autoTypeSource, result, errors);
	delete[] data;
	return ok;
}


CoreTypeParser::CoreTypeParser(BNTypeParser* parser): TypeParser(parser)
{

}


bool CoreTypeParser::GetOptionText(BNTypeParserOption option, std::string value, std::string& result) const
{
	char* apiResult;
	if (!BNGetTypeParserOptionText(m_object, option, value.c_str(), &apiResult))
		return false;
	result = apiResult;
	BNFreeString(apiResult);
	return true;
}


bool CoreTypeParser::PreprocessSource(const std::string& source, const std::string& fileName,
	Ref<Platform> platform, std::optional<TypeContainer> existingTypes,
	const std::vector<std::string>& options, const std::vector<std::string>& includeDirs,
	std::string& output, std::vector<TypeParserError>& errors)
{
	BNTypeContainer* apiExistingTypes = (existingTypes.has_value() ? existingTypes->GetObject() : nullptr);

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

	char* apiOutput;
	BNTypeParserError* apiErrors;
	size_t errorCount;

	auto success = BNTypeParserPreprocessSource(m_object, source.c_str(), fileName.c_str(),
		platform->GetObject(), apiExistingTypes,
		apiOptions, options.size(), apiIncludeDirs, includeDirs.size(), &apiOutput,
		&apiErrors, &errorCount);

	delete [] apiOptions;
	delete [] apiIncludeDirs;

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
	Ref<Platform> platform, std::optional<TypeContainer> existingTypes,
	const std::vector<std::string>& options, const std::vector<std::string>& includeDirs,
	const std::string& autoTypeSource, TypeParserResult& result, std::vector<TypeParserError>& errors)
{
	BNTypeContainer* apiExistingTypes = (existingTypes.has_value() ? existingTypes->GetObject() : nullptr);

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

	BNTypeParserResult apiResult;
	BNTypeParserError* apiErrors;
	size_t errorCount;

	auto success = BNTypeParserParseTypesFromSource(m_object, source.c_str(), fileName.c_str(),
		platform->GetObject(), apiExistingTypes,
		apiOptions, options.size(), apiIncludeDirs, includeDirs.size(), autoTypeSource.c_str(), &apiResult,
		&apiErrors, &errorCount);

	delete [] apiOptions;
	delete [] apiIncludeDirs;

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
			apiResult.variables[j].isUser
		});
	}

	result.functions.clear();
	for (size_t j = 0; j < apiResult.functionCount; ++j)
	{
		result.functions.push_back({
			QualifiedName::FromAPIObject(&apiResult.functions[j].name),
			new Type(BNNewTypeReference(apiResult.functions[j].type)),
			apiResult.functions[j].isUser
		});
	}

	BNFreeTypeParserResult(&apiResult);
	return true;
}


bool CoreTypeParser::ParseTypeString(const std::string& source, Ref<Platform> platform,
	std::optional<TypeContainer> existingTypes,
	QualifiedNameAndType& result, std::vector<TypeParserError>& errors)
{
	BNTypeContainer* apiExistingTypes = (existingTypes.has_value() ? existingTypes->GetObject() : nullptr);

	BNQualifiedNameAndType apiResult;
	BNTypeParserError* apiErrors;
	size_t errorCount;

	auto success = BNTypeParserParseTypeString(m_object, source.c_str(), platform->GetObject(),
		apiExistingTypes, &apiResult,
		&apiErrors, &errorCount);

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
