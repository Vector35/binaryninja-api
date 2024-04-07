// Copyright (c) 2015-2024 Vector 35 Inc
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include "binaryninjaapi.h"

using namespace BinaryNinja;


TypeContainer::TypeContainer(BNTypeContainer* container): m_object(container)
{

}


TypeContainer::TypeContainer(TypeContainer&& other)
{
	m_object = std::move(other.m_object);
	other.m_object = nullptr;
}


TypeContainer::TypeContainer(Ref<BinaryView> data)
{
	auto container = data->GetTypeContainer();
	m_object = BNDuplicateTypeContainer(container.m_object);
}


TypeContainer::TypeContainer(Ref<TypeLibrary> library)
{
	auto container = library->GetTypeContainer();
	m_object = BNDuplicateTypeContainer(container.m_object);
}


TypeContainer::TypeContainer(Ref<TypeArchive> archive)
{
	auto container = archive->GetTypeContainer();
	m_object = BNDuplicateTypeContainer(container.m_object);
}


TypeContainer::TypeContainer(Ref<Platform> platform)
{
	auto container = platform->GetTypeContainer();
	m_object = BNDuplicateTypeContainer(container.m_object);
}


TypeContainer::~TypeContainer()
{
	if (m_object)
		BNFreeTypeContainer(m_object);
	m_object = nullptr;
}


TypeContainer::TypeContainer(const TypeContainer& other)
{
	m_object = BNDuplicateTypeContainer(other.m_object);
}


TypeContainer& TypeContainer::operator=(const TypeContainer& other)
{
	m_object = BNDuplicateTypeContainer(other.m_object);
	return *this;
}


TypeContainer& TypeContainer::operator=(TypeContainer&& other)
{
	m_object = std::move(other.m_object);
	other.m_object = nullptr;
	return *this;
}


std::string TypeContainer::GetId() const
{
	char* id = BNTypeContainerGetId(m_object);
	std::string result = id;
	BNFreeString(id);
	return result;
}


std::string TypeContainer::GetName() const
{
	char* name = BNTypeContainerGetName(m_object);
	std::string result = name;
	BNFreeString(name);
	return result;
}


BNTypeContainerType TypeContainer::GetType() const
{
	return BNTypeContainerGetType(m_object);
}


bool TypeContainer::IsMutable() const
{
	return BNTypeContainerIsMutable(m_object);
}


Ref<Platform> TypeContainer::GetPlatform() const
{
	BNPlatform* platform = BNTypeContainerGetPlatform(m_object);
	if (!platform)
		return nullptr;
	return new Platform(platform);
}


std::optional<std::string> TypeContainer::AddType(QualifiedName name, Ref<Type> type)
{
	auto result = AddTypes({std::make_pair(name, type)});
	if (!result.has_value())
		return std::nullopt;

	auto found = result->find(name);
	if (found != result->end())
	{
		return found->second;
	}
	return std::nullopt;
}


std::optional<std::unordered_map<QualifiedName, std::string>> TypeContainer::AddTypes(
	const std::vector<std::pair<QualifiedName, Ref<Type>>>& types,
	std::function<bool(size_t, size_t)> progress)
{
	BNQualifiedName* apiTypeNames = new BNQualifiedName[types.size()];
	BNType** apiTypes = new BNType*[types.size()];
	for (size_t i = 0; i < types.size(); i++)
	{
		apiTypeNames[i] = types[i].first.GetAPIObject();
		apiTypes[i] = types[i].second->GetObject();
	}

	ProgressContext apiProgress;
	if (progress)
		apiProgress.callback = progress;
	else
		apiProgress.callback = [](size_t, size_t) { return true; };

	char** resultIds;
	BNQualifiedName* resultNames;
	size_t resultCount;
	bool success = BNTypeContainerAddTypes(m_object, apiTypeNames, apiTypes, types.size(), ProgressCallback, &apiProgress, &resultNames, &resultIds, &resultCount);

	for (size_t i = 0; i < types.size(); i++)
	{
		QualifiedName::FreeAPIObject(&apiTypeNames[i]);
	}
	delete[] apiTypeNames;
	delete[] apiTypes;
	if (!success)
		return {};

	std::unordered_map<QualifiedName, std::string> result;
	for (size_t i = 0; i < resultCount; i++)
	{
		result[QualifiedName::FromAPIObject(&resultNames[i])] = resultIds[i];
	}
	BNFreeStringList(resultIds, resultCount);
	BNFreeTypeNameList(resultNames, resultCount);

	return result;
}


bool TypeContainer::RenameType(const std::string& typeId, const QualifiedName& newName)
{
	BNQualifiedName apiNewName = newName.GetAPIObject();
	bool success = BNTypeContainerRenameType(m_object, typeId.c_str(), &apiNewName);
	QualifiedName::FreeAPIObject(&apiNewName);
	return success;
}


bool TypeContainer::DeleteType(const std::string& typeId)
{
	return BNTypeContainerDeleteType(m_object, typeId.c_str());
}


std::optional<std::string> TypeContainer::GetTypeId(const QualifiedName& typeName) const
{
	BNQualifiedName apiTypeName = typeName.GetAPIObject();
	char* result;
	bool success = BNTypeContainerGetTypeId(m_object, &apiTypeName, &result);
	QualifiedName::FreeAPIObject(&apiTypeName);
	if (!success)
		return {};
	return std::string(result);
}


std::optional<QualifiedName> TypeContainer::GetTypeName(const std::string& typeId) const
{
	BNQualifiedName apiResult;
	if (!BNTypeContainerGetTypeName(m_object, typeId.c_str(), &apiResult))
		return {};
	QualifiedName result = QualifiedName::FromAPIObject(&apiResult);
	BNFreeQualifiedName(&apiResult);
	return result;
}


std::optional<Ref<Type>> TypeContainer::GetTypeById(const std::string& typeId) const
{
	BNType* apiResult;
	if (!BNTypeContainerGetTypeById(m_object, typeId.c_str(), &apiResult))
		return {};
	return new Type(apiResult);
}


std::optional<std::unordered_map<std::string, std::pair<QualifiedName, Ref<Type>>>> TypeContainer::GetTypes() const
{
	char** resultIds;
	BNQualifiedName* resultNames;
	BNType** resultTypes;
	size_t resultCount;
	if (!BNTypeContainerGetTypes(m_object, &resultIds, &resultNames, &resultTypes, &resultCount))
		return {};

	std::unordered_map<std::string, std::pair<QualifiedName, Ref<Type>>> result;
	for (size_t i = 0; i < resultCount; i++)
	{
		result[resultIds[i]] = std::make_pair(QualifiedName::FromAPIObject(&resultNames[i]), new Type(
			BNNewTypeReference(resultTypes[i])));
	}
	BNFreeStringList(resultIds, resultCount);
	BNFreeTypeNameList(resultNames, resultCount);
	BNFreeTypeList(resultTypes, resultCount);

	return result;
}


std::optional<Ref<Type>> TypeContainer::GetTypeByName(const QualifiedName& typeName) const
{
	BNQualifiedName apiTypeName = typeName.GetAPIObject();
	BNType* apiResult;
	bool success = BNTypeContainerGetTypeByName(m_object, &apiTypeName, &apiResult);
	QualifiedName::FreeAPIObject(&apiTypeName);
	if (!success)
		return {};
	return new Type(apiResult);
}


std::optional<std::unordered_set<std::string>> TypeContainer::GetTypeIds() const
{
	char** resultIds;
	size_t resultCount;
	if (!BNTypeContainerGetTypeIds(m_object, &resultIds, &resultCount))
		return {};

	std::unordered_set<std::string> result;
	for (size_t i = 0; i < resultCount; i++)
	{
		result.insert(resultIds[i]);
	}
	BNFreeStringList(resultIds, resultCount);

	return result;
}


std::optional<std::unordered_set<QualifiedName>> TypeContainer::GetTypeNames() const
{
	BNQualifiedName* resultNames;
	size_t resultCount;
	if (!BNTypeContainerGetTypeNames(m_object, &resultNames, &resultCount))
		return {};

	std::unordered_set<QualifiedName> result;
	for (size_t i = 0; i < resultCount; i++)
	{
		result.insert(QualifiedName::FromAPIObject(&resultNames[i]));
	}
	BNFreeTypeNameList(resultNames, resultCount);

	return result;
}


std::optional<std::unordered_map<std::string, QualifiedName>> TypeContainer::GetTypeNamesAndIds() const
{
	char** resultIds;
	BNQualifiedName* resultNames;
	size_t resultCount;
	if (!BNTypeContainerGetTypeNamesAndIds(m_object, &resultIds, &resultNames, &resultCount))
		return {};

	std::unordered_map<std::string, QualifiedName> result;
	for (size_t i = 0; i < resultCount; i++)
	{
		result[resultIds[i]] = QualifiedName::FromAPIObject(&resultNames[i]);
	}
	BNFreeStringList(resultIds, resultCount);
	BNFreeTypeNameList(resultNames, resultCount);

	return result;
}


bool TypeContainer::ParseTypeString(
	const std::string& source,
	bool importDependencies,
	BinaryNinja::QualifiedNameAndType& result,
	std::vector<TypeParserError>& errors
)
{
	BNQualifiedNameAndType apiResult;
	BNTypeParserError* apiErrors;
	size_t errorCount;

	auto success = BNTypeContainerParseTypeString(m_object, source.c_str(), importDependencies, &apiResult,
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

	result.type = new Type(BNNewTypeReference(apiResult.type));
	result.name = QualifiedName::FromAPIObject(&apiResult.name);

	BNFreeQualifiedNameAndType(&apiResult);
	return true;
}


bool TypeContainer::ParseTypeString(
	const std::string& source,
	BinaryNinja::QualifiedNameAndType& result,
	std::vector<TypeParserError>& errors
)
{
	return ParseTypeString(source, true, result, errors);
}


bool TypeContainer::ParseTypesFromSource(
	const std::string& text,
	const std::string& fileName,
	const std::vector<std::string>& options,
	const std::vector<std::string>& includeDirs,
	const std::string& autoTypeSource,
	bool importDependencies,
	BinaryNinja::TypeParserResult& result,
	std::vector<TypeParserError>& errors
)
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

	BNTypeParserResult apiResult;
	BNTypeParserError* apiErrors;
	size_t errorCount;

	auto success = BNTypeContainerParseTypesFromSource(m_object, text.c_str(), fileName.c_str(),
		apiOptions, options.size(), apiIncludeDirs, includeDirs.size(), autoTypeSource.c_str(), importDependencies,
		&apiResult, &apiErrors, &errorCount);

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


bool TypeContainer::ParseTypesFromSource(
	const std::string& text,
	const std::string& fileName,
	const std::vector<std::string>& options,
	const std::vector<std::string>& includeDirs,
	const std::string& autoTypeSource,
	BinaryNinja::TypeParserResult& result,
	std::vector<TypeParserError>& errors
)
{
	return ParseTypesFromSource(
		text,
		fileName,
		options,
		includeDirs,
		autoTypeSource,
		true,
		result,
		errors
	);
}
