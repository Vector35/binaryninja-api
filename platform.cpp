// Copyright (c) 2015-2023 Vector 35 Inc
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

using namespace std;
using namespace BinaryNinja;


Platform::Platform(BNPlatform* platform)
{
	m_object = platform;
}


Platform::Platform(Architecture* arch, const string& name)
{
	m_object = BNCreatePlatform(arch->GetObject(), name.c_str());
}


Platform::Platform(Architecture* arch, const string& name, const string& typeFile, const vector<string>& includeDirs)
{
	const char** includeDirList = new const char*[includeDirs.size()];
	for (size_t i = 0; i < includeDirs.size(); i++)
		includeDirList[i] = includeDirs[i].c_str();
	m_object = BNCreatePlatformWithTypes(
	    arch->GetObject(), name.c_str(), typeFile.c_str(), includeDirList, includeDirs.size());
	delete[] includeDirList;
}


Ref<Architecture> Platform::GetArchitecture() const
{
	return new CoreArchitecture(BNGetPlatformArchitecture(m_object));
}


string Platform::GetName() const
{
	char* str = BNGetPlatformName(m_object);
	string result = str;
	BNFreeString(str);
	return result;
}


void Platform::Register(const string& os, Platform* platform)
{
	BNRegisterPlatform(os.c_str(), platform->GetObject());
}


Ref<Platform> Platform::GetByName(const string& name)
{
	BNPlatform* platform = BNGetPlatformByName(name.c_str());
	if (!platform)
		return nullptr;
	return new Platform(platform);
}


vector<Ref<Platform>> Platform::GetList()
{
	size_t count;
	BNPlatform** list = BNGetPlatformList(&count);

	vector<Ref<Platform>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Platform(BNNewPlatformReference(list[i])));

	BNFreePlatformList(list, count);
	return result;
}


vector<Ref<Platform>> Platform::GetList(Architecture* arch)
{
	size_t count;
	BNPlatform** list = BNGetPlatformListByArchitecture(arch->GetObject(), &count);

	vector<Ref<Platform>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Platform(BNNewPlatformReference(list[i])));

	BNFreePlatformList(list, count);
	return result;
}


vector<Ref<Platform>> Platform::GetList(const string& os)
{
	size_t count;
	BNPlatform** list = BNGetPlatformListByOS(os.c_str(), &count);

	vector<Ref<Platform>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Platform(BNNewPlatformReference(list[i])));

	BNFreePlatformList(list, count);
	return result;
}


vector<Ref<Platform>> Platform::GetList(const string& os, Architecture* arch)
{
	size_t count;
	BNPlatform** list = BNGetPlatformListByOSAndArchitecture(os.c_str(), arch->GetObject(), &count);

	vector<Ref<Platform>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Platform(BNNewPlatformReference(list[i])));

	BNFreePlatformList(list, count);
	return result;
}


vector<std::string> Platform::GetOSList()
{
	size_t count;
	char** list = BNGetPlatformOSList(&count);

	vector<string> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(list[i]);

	BNFreePlatformOSList(list, count);
	return result;
}


Ref<CallingConvention> Platform::GetDefaultCallingConvention() const
{
	BNCallingConvention* cc = BNGetPlatformDefaultCallingConvention(m_object);
	if (!cc)
		return nullptr;
	return new CoreCallingConvention(cc);
}


Ref<CallingConvention> Platform::GetCdeclCallingConvention() const
{
	BNCallingConvention* cc = BNGetPlatformCdeclCallingConvention(m_object);
	if (!cc)
		return nullptr;
	return new CoreCallingConvention(cc);
}


Ref<CallingConvention> Platform::GetStdcallCallingConvention() const
{
	BNCallingConvention* cc = BNGetPlatformStdcallCallingConvention(m_object);
	if (!cc)
		return nullptr;
	return new CoreCallingConvention(cc);
}


Ref<CallingConvention> Platform::GetFastcallCallingConvention() const
{
	BNCallingConvention* cc = BNGetPlatformFastcallCallingConvention(m_object);
	if (!cc)
		return nullptr;
	return new CoreCallingConvention(cc);
}


vector<Ref<CallingConvention>> Platform::GetCallingConventions() const
{
	size_t count;
	BNCallingConvention** list = BNGetPlatformCallingConventions(m_object, &count);

	vector<Ref<CallingConvention>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreCallingConvention(BNNewCallingConventionReference(list[i])));

	BNFreeCallingConventionList(list, count);
	return result;
}


Ref<CallingConvention> Platform::GetSystemCallConvention() const
{
	BNCallingConvention* cc = BNGetPlatformSystemCallConvention(m_object);
	if (!cc)
		return nullptr;
	return new CoreCallingConvention(cc);
}


void Platform::RegisterCallingConvention(CallingConvention* cc)
{
	BNRegisterPlatformCallingConvention(m_object, cc->GetObject());
}


void Platform::RegisterDefaultCallingConvention(CallingConvention* cc)
{
	BNRegisterPlatformDefaultCallingConvention(m_object, cc->GetObject());
}


void Platform::RegisterCdeclCallingConvention(CallingConvention* cc)
{
	BNRegisterPlatformCdeclCallingConvention(m_object, cc->GetObject());
}


void Platform::RegisterStdcallCallingConvention(CallingConvention* cc)
{
	BNRegisterPlatformStdcallCallingConvention(m_object, cc->GetObject());
}


void Platform::RegisterFastcallCallingConvention(CallingConvention* cc)
{
	BNRegisterPlatformFastcallCallingConvention(m_object, cc->GetObject());
}


void Platform::SetSystemCallConvention(CallingConvention* cc)
{
	BNSetPlatformSystemCallConvention(m_object, cc ? cc->GetObject() : nullptr);
}


Ref<Platform> Platform::GetRelatedPlatform(Architecture* arch)
{
	BNPlatform* platform = BNGetRelatedPlatform(m_object, arch->GetObject());
	if (!platform)
		return nullptr;
	return new Platform(platform);
}


void Platform::AddRelatedPlatform(Architecture* arch, Platform* platform)
{
	BNAddRelatedPlatform(m_object, arch->GetObject(), platform->GetObject());
}


Ref<Platform> Platform::GetAssociatedPlatformByAddress(uint64_t& addr)
{
	BNPlatform* platform = BNGetAssociatedPlatformByAddress(m_object, &addr);
	if (!platform)
		return nullptr;
	return new Platform(platform);
}


map<QualifiedName, Ref<Type>> Platform::GetTypes()
{
	size_t count;
	BNQualifiedNameAndType* types = BNGetPlatformTypes(m_object, &count);

	map<QualifiedName, Ref<Type>> result;
	for (size_t i = 0; i < count; i++)
	{
		QualifiedName name = QualifiedName::FromAPIObject(&types[i].name);
		result[name] = new Type(BNNewTypeReference(types[i].type));
	}

	BNFreeTypeAndNameList(types, count);
	return result;
}


map<QualifiedName, Ref<Type>> Platform::GetVariables()
{
	size_t count;
	BNQualifiedNameAndType* types = BNGetPlatformVariables(m_object, &count);

	map<QualifiedName, Ref<Type>> result;
	for (size_t i = 0; i < count; i++)
	{
		QualifiedName name = QualifiedName::FromAPIObject(&types[i].name);
		result[name] = new Type(BNNewTypeReference(types[i].type));
	}

	BNFreeTypeAndNameList(types, count);
	return result;
}


map<QualifiedName, Ref<Type>> Platform::GetFunctions()
{
	size_t count;
	BNQualifiedNameAndType* types = BNGetPlatformFunctions(m_object, &count);

	map<QualifiedName, Ref<Type>> result;
	for (size_t i = 0; i < count; i++)
	{
		QualifiedName name = QualifiedName::FromAPIObject(&types[i].name);
		result[name] = new Type(BNNewTypeReference(types[i].type));
	}

	BNFreeTypeAndNameList(types, count);
	return result;
}


map<uint32_t, QualifiedNameAndType> Platform::GetSystemCalls()
{
	size_t count;
	BNSystemCallInfo* calls = BNGetPlatformSystemCalls(m_object, &count);

	map<uint32_t, QualifiedNameAndType> result;
	for (size_t i = 0; i < count; i++)
	{
		QualifiedNameAndType nt;
		nt.name = QualifiedName::FromAPIObject(&calls[i].name);
		nt.type = new Type(BNNewTypeReference(calls[i].type));
		result[calls[i].number] = nt;
	}

	BNFreeSystemCallList(calls, count);
	return result;
}


vector<Ref<TypeLibrary>> Platform::GetTypeLibraries()
{
	size_t count;
	BNTypeLibrary** libs = BNGetPlatformTypeLibraries(m_object, &count);

	vector<Ref<TypeLibrary>> result;
	for (size_t i = 0; i < count; ++i)
	{
		result.push_back(new TypeLibrary(BNNewTypeLibraryReference(libs[i])));
	}

	BNFreeTypeLibraryList(libs, count);
	return result;
}


vector<Ref<TypeLibrary>> Platform::GetTypeLibrariesByName(const std::string& name)
{
	size_t count;
	BNTypeLibrary** libs = BNGetPlatformTypeLibrariesByName(m_object, name.c_str(), &count);

	vector<Ref<TypeLibrary>> result;
	for (size_t i = 0; i < count; ++i)
	{
		result.push_back(new TypeLibrary(BNNewTypeLibraryReference(libs[i])));
	}

	BNFreeTypeLibraryList(libs, count);
	return result;
}


TypeContainer Platform::GetTypeContainer()
{
	return TypeContainer(BNGetPlatformTypeContainer(m_object));
}


Ref<Type> Platform::GetTypeByName(const QualifiedName& name)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	BNType* type = BNGetPlatformTypeByName(m_object, &nameObj);
	QualifiedName::FreeAPIObject(&nameObj);
	if (!type)
		return nullptr;
	return new Type(type);
}


Ref<Type> Platform::GetVariableByName(const QualifiedName& name)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	BNType* type = BNGetPlatformVariableByName(m_object, &nameObj);
	QualifiedName::FreeAPIObject(&nameObj);
	if (!type)
		return nullptr;
	return new Type(type);
}


Ref<Type> Platform::GetFunctionByName(const QualifiedName& name, bool exactMatch)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	BNType* type = BNGetPlatformFunctionByName(m_object, &nameObj, exactMatch);
	QualifiedName::FreeAPIObject(&nameObj);
	if (!type)
		return nullptr;
	return new Type(type);
}


string Platform::GetSystemCallName(uint32_t n)
{
	char* str = BNGetPlatformSystemCallName(m_object, n);
	string result = str;
	BNFreeString(str);
	return result;
}


Ref<Type> Platform::GetSystemCallType(uint32_t n)
{
	BNType* type = BNGetPlatformSystemCallType(m_object, n);
	if (!type)
		return nullptr;
	return new Type(type);
}


string Platform::GenerateAutoPlatformTypeId(const QualifiedName& name)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	char* str = BNGenerateAutoPlatformTypeId(m_object, &nameObj);
	string result = str;
	QualifiedName::FreeAPIObject(&nameObj);
	BNFreeString(str);
	return result;
}


Ref<NamedTypeReference> Platform::GenerateAutoPlatformTypeReference(
    BNNamedTypeReferenceClass cls, const QualifiedName& name)
{
	string id = GenerateAutoPlatformTypeId(name);
	return new NamedTypeReference(cls, id, name);
}


string Platform::GetAutoPlatformTypeIdSource()
{
	char* str = BNGetAutoPlatformTypeIdSource(m_object);
	string result = str;
	BNFreeString(str);
	return result;
}


bool Platform::ParseTypesFromSource(const string& source, const string& fileName, map<QualifiedName, Ref<Type>>& types,
    map<QualifiedName, Ref<Type>>& variables, map<QualifiedName, Ref<Type>>& functions, string& errors,
    const vector<string>& includeDirs, const string& autoTypeSource)
{
	BNTypeParserResult result;
	char* errorStr;
	const char** includeDirList = new const char*[includeDirs.size()];

	for (size_t i = 0; i < includeDirs.size(); i++)
		includeDirList[i] = includeDirs[i].c_str();

	types.clear();
	variables.clear();
	functions.clear();

	bool ok = BNParseTypesFromSource(m_object, source.c_str(), fileName.c_str(), &result, &errorStr, includeDirList,
	    includeDirs.size(), autoTypeSource.c_str());
	errors = errorStr;
	BNFreeString(errorStr);
	delete[] includeDirList;
	if (!ok)
		return false;

	for (size_t i = 0; i < result.typeCount; i++)
	{
		QualifiedName name = QualifiedName::FromAPIObject(&result.types[i].name);
		types[name] = new Type(BNNewTypeReference(result.types[i].type));
	}
	for (size_t i = 0; i < result.variableCount; i++)
	{
		QualifiedName name = QualifiedName::FromAPIObject(&result.variables[i].name);
		variables[name] = new Type(BNNewTypeReference(result.variables[i].type));
	}
	for (size_t i = 0; i < result.functionCount; i++)
	{
		QualifiedName name = QualifiedName::FromAPIObject(&result.functions[i].name);
		functions[name] = new Type(BNNewTypeReference(result.functions[i].type));
	}
	BNFreeTypeParserResult(&result);
	return true;
}


bool Platform::ParseTypesFromSourceFile(const string& fileName, map<QualifiedName, Ref<Type>>& types,
    map<QualifiedName, Ref<Type>>& variables, map<QualifiedName, Ref<Type>>& functions, string& errors,
    const vector<string>& includeDirs, const string& autoTypeSource)
{
	BNTypeParserResult result;
	char* errorStr;
	const char** includeDirList = new const char*[includeDirs.size()];

	for (size_t i = 0; i < includeDirs.size(); i++)
		includeDirList[i] = includeDirs[i].c_str();

	types.clear();
	variables.clear();
	functions.clear();

	bool ok = BNParseTypesFromSourceFile(
	    m_object, fileName.c_str(), &result, &errorStr, includeDirList, includeDirs.size(), autoTypeSource.c_str());
	errors = errorStr;
	BNFreeString(errorStr);
	delete[] includeDirList;
	if (!ok)
		return false;

	for (size_t i = 0; i < result.typeCount; i++)
	{
		QualifiedName name = QualifiedName::FromAPIObject(&result.types[i].name);
		types[name] = new Type(BNNewTypeReference(result.types[i].type));
	}
	for (size_t i = 0; i < result.variableCount; i++)
	{
		QualifiedName name = QualifiedName::FromAPIObject(&result.variables[i].name);
		variables[name] = new Type(BNNewTypeReference(result.variables[i].type));
	}
	for (size_t i = 0; i < result.functionCount; i++)
	{
		QualifiedName name = QualifiedName::FromAPIObject(&result.functions[i].name);
		functions[name] = new Type(BNNewTypeReference(result.functions[i].type));
	}
	BNFreeTypeParserResult(&result);
	return true;
}
