// Copyright (c) 2015-2016 Vector 35 LLC
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
using namespace std;


Type::Type(BNType* type)
{
	m_object = type;
}


BNTypeClass Type::GetClass() const
{
	return BNGetTypeClass(m_object);
}


uint64_t Type::GetWidth() const
{
	return BNGetTypeWidth(m_object);
}


size_t Type::GetAlignment() const
{
	return BNGetTypeAlignment(m_object);
}


bool Type::IsSigned() const
{
	return BNIsTypeSigned(m_object);
}


bool Type::IsConst() const
{
	return BNIsTypeConst(m_object);
}


bool Type::IsFloat() const
{
	return BNIsTypeFloatingPoint(m_object);
}


Ref<Type> Type::GetChildType() const
{
	BNType* type = BNGetChildType(m_object);
	if (type)
		return new Type(type);
	return nullptr;
}


Ref<CallingConvention> Type::GetCallingConvention() const
{
	BNCallingConvention* cc = BNGetTypeCallingConvention(m_object);
	if (cc)
		return new CoreCallingConvention(cc);
	return nullptr;
}


vector<NameAndType> Type::GetParameters() const
{
	size_t count;
	BNNameAndType* types = BNGetTypeParameters(m_object, &count);

	vector<NameAndType> result;
	for (size_t i = 0; i < count; i++)
	{
		NameAndType param;
		param.name = types[i].name;
		param.type = new Type(BNNewTypeReference(types[i].type));
		result.push_back(param);
	}

	BNFreeTypeParameterList(types, count);
	return result;
}


bool Type::HasVariableArguments() const
{
	return BNTypeHasVariableArguments(m_object);
}


bool Type::CanReturn() const
{
	return BNFunctionTypeCanReturn(m_object);
}


Ref<Structure> Type::GetStructure() const
{
	BNStructure* s = BNGetTypeStructure(m_object);
	if (s)
		return new Structure(s);
	return nullptr;
}


Ref<Enumeration> Type::GetEnumeration() const
{
	BNEnumeration* e = BNGetTypeEnumeration(m_object);
	if (e)
		return new Enumeration(e);
	return nullptr;
}


uint64_t Type::GetElementCount() const
{
	return BNGetTypeElementCount(m_object);
}


string Type::GetQualifiedName(const vector<string>& names)
{
	bool first = true;
	string out;
	for (auto &name : names)
	{
		if (!first)
		{
			out += "::" + name;
		}
		else
		{
			out += name;
		}
		if (name.length() != 0)
			first = false;
	}
	return out;
}


string Type::GetString() const
{
	char* str = BNGetTypeString(m_object);
	string result = str;
	BNFreeString(str);
	return result;
}


string Type::GetTypeAndName(const vector<string>& nameList) const
{
	const char ** str = new const char*[nameList.size()];
	for (size_t i = 0; i < nameList.size(); i++)
	{
		str[i] = nameList[i].c_str();
	}
	char* outName = BNGetTypeAndName(m_object, str, nameList.size());
	delete [] str;
	return outName;
}

string Type::GetStringBeforeName() const
{
	char* str = BNGetTypeStringBeforeName(m_object);
	string result = str;
	BNFreeString(str);
	return result;
}


string Type::GetStringAfterName() const
{
	char* str = BNGetTypeStringAfterName(m_object);
	string result = str;
	BNFreeString(str);
	return result;
}


Ref<Type> Type::Duplicate() const
{
	return new Type(BNDuplicateType(m_object));
}


Ref<Type> Type::VoidType()
{
	return new Type(BNCreateVoidType());
}


Ref<Type> Type::BoolType()
{
	return new Type(BNCreateBoolType());
}


Ref<Type> Type::IntegerType(size_t width, bool sign, const string& altName)
{
	return new Type(BNCreateIntegerType(width, sign, altName.c_str()));
}


Ref<Type> Type::FloatType(size_t width, const string& altName)
{
	return new Type(BNCreateFloatType(width, altName.c_str()));
}


Ref<Type> Type::StructureType(Structure* strct)
{
	return new Type(BNCreateStructureType(strct->GetObject()));
}


Ref<Type> Type::UnknownNamedType(UnknownType* unknwn)
{
	return new Type(BNCreateUnknownNamedType(unknwn->GetObject()));
}


Ref<Type> Type::EnumerationType(Architecture* arch, Enumeration* enm, size_t width, bool isSigned)
{
	return new Type(BNCreateEnumerationType(arch->GetObject(), enm->GetObject(), width, isSigned));
}


Ref<Type> Type::PointerType(Architecture* arch, Type* type, bool cnst, bool vltl, BNReferenceType refType)
{
	return new Type(BNCreatePointerType(arch->GetObject(), type->GetObject(), cnst, vltl, refType));
}


Ref<Type> Type::ArrayType(Type* type, uint64_t elem)
{
	return new Type(BNCreateArrayType(type->GetObject(), elem));
}


Ref<Type> Type::FunctionType(Type* returnValue, CallingConvention* callingConvention,
                             const std::vector<NameAndType>& params, bool varArg)
{
	BNNameAndType* paramArray = new BNNameAndType[params.size()];
	for (size_t i = 0; i < params.size(); i++)
	{
		paramArray[i].name = (char*)params[i].name.c_str();
		paramArray[i].type = params[i].type->GetObject();
	}

	Type* type = new Type(BNCreateFunctionType(returnValue->GetObject(),
	                      callingConvention ? callingConvention->GetObject() : nullptr,
	                      paramArray, params.size(), varArg));
	delete[] paramArray;
	return type;
}


void Type::SetFunctionCanReturn(bool canReturn)
{
	BNSetFunctionCanReturn(m_object, canReturn);
}


UnknownType::UnknownType(BNUnknownType* ut, vector<string> names)
{
	m_object = ut;
	const char ** nameList = new const char*[names.size()];
	for (size_t i = 0; i < names.size(); i++)
	{
		nameList[i] = names[i].c_str();
	}
	BNSetUnknownTypeName(ut, nameList, names.size());
	delete [] nameList;
}


void UnknownType::SetName(const vector<string>& names)
{
	const char ** nameList = new const char*[names.size()];
	for (size_t i = 0; i < names.size(); i++)
	{
		nameList[i] = names[i].c_str();
	}
	BNSetUnknownTypeName(m_object, nameList, names.size());
	delete [] nameList;
}


vector<string> UnknownType::GetName() const
{
	size_t size;
	char** name = BNGetUnknownTypeName(m_object, &size);
	vector<string> result;
	for (size_t i = 0; i < size; i++)
	{
		result.push_back(name[i]);
		BNFreeString(name[i]);
	}
	delete [] name;
	return result;
}


Structure::Structure()
{
	m_object = BNCreateStructure();
}


Structure::Structure(BNStructure* s)
{
	m_object = s;
}


vector<string> Structure::GetName() const
{
	size_t size;
	char** name = BNGetStructureName(m_object, &size);
	vector<string> result;
	for (size_t i = 0; i < size; i++)
	{
		result.push_back(name[i]);
		BNFreeString(name[i]);
	}
	delete [] name;
	return result;
}


void Structure::SetName(const vector<string>& names)
{
	const char ** nameList = new const char*[names.size()];
	for (size_t i = 0; i < names.size(); i++)
	{
		nameList[i] = names[i].c_str();
	}
	BNSetStructureName(m_object, nameList, names.size());
	delete [] nameList;
}


vector<StructureMember> Structure::GetMembers() const
{
	size_t count;
	BNStructureMember* members = BNGetStructureMembers(m_object, &count);

	vector<StructureMember> result;
	for (size_t i = 0; i < count; i++)
	{
		StructureMember member;
		member.type = new Type(BNNewTypeReference(members[i].type));
		member.name = members[i].name;
		member.offset = members[i].offset;
		result.push_back(member);
	}

	BNFreeStructureMemberList(members, count);
	return result;
}


uint64_t Structure::GetWidth() const
{
	return BNGetStructureWidth(m_object);
}


void Structure::SetWidth(size_t width)
{
	BNSetStructureWidth(m_object, width);
}


size_t Structure::GetAlignment() const
{
	return BNGetStructureAlignment(m_object);
}


void Structure::SetAlignment(size_t align)
{
	BNSetStructureAlignment(m_object, align);
}


bool Structure::IsPacked() const
{
	return BNIsStructurePacked(m_object);
}


void Structure::SetPacked(bool packed)
{
	BNSetStructurePacked(m_object, packed);
}


bool Structure::IsUnion() const
{
	return BNIsStructureUnion(m_object);
}


void Structure::SetUnion(bool u)
{
	BNSetStructureUnion(m_object, u);
}


void Structure::AddMember(Type* type, const string& name)
{
	BNAddStructureMember(m_object, type->GetObject(), name.c_str());
}


void Structure::AddMemberAtOffset(Type* type, const string& name, uint64_t offset)
{
	BNAddStructureMemberAtOffset(m_object, type->GetObject(), name.c_str(), offset);
}


void Structure::RemoveMember(size_t idx)
{
	BNRemoveStructureMember(m_object, idx);
}


void Structure::ReplaceMember(size_t idx, Type* type, const std::string& name)
{
	BNReplaceStructureMember(m_object, idx, type->GetObject(), name.c_str());
}


Enumeration::Enumeration(BNEnumeration* e)
{
	m_object = e;
}


vector<string> Enumeration::GetName() const
{
	vector<string> result;
	size_t size;
	char** name = BNGetEnumerationName(m_object, &size);
	for (size_t i = 0; i < size; i++)
	{
		result.push_back(name[i]);
		BNFreeString(name[i]);
	}
	delete [] name;
	return result;
}

void Enumeration::SetName(const vector<string>& names)
{
	const char **const nameList = new const char*[names.size()];
	for (size_t i = 0; i < names.size(); i++)
	{
		nameList[i] = names[i].c_str();
	}
	BNSetEnumerationName(m_object, nameList, names.size());
	delete [] nameList;
}


vector<EnumerationMember> Enumeration::GetMembers() const
{
	size_t count;
	BNEnumerationMember* members = BNGetEnumerationMembers(m_object, &count);

	vector<EnumerationMember> result;
	for (size_t i = 0; i < count; i++)
	{
		EnumerationMember member;
		member.name = members[i].name;
		member.value = members[i].value;
		member.isDefault = members[i].isDefault;
		result.push_back(member);
	}

	BNFreeEnumerationMemberList(members, count);
	return result;
}


void Enumeration::AddMember(const string& name)
{
	BNAddEnumerationMember(m_object, name.c_str());
}


void Enumeration::AddMemberWithValue(const string& name, uint64_t value)
{
	BNAddEnumerationMemberWithValue(m_object, name.c_str(), value);
}


void Enumeration::RemoveMember(size_t idx)
{
	BNRemoveEnumerationMember(m_object, idx);
}


void Enumeration::ReplaceMember(size_t idx, const string& name, uint64_t value)
{
	BNReplaceEnumerationMember(m_object, idx, name.c_str(), value);
}


bool BinaryNinja::PreprocessSource(const string& source, const string& fileName, string& output, string& errors,
                                   const vector<string>& includeDirs)
{
	char* outStr;
	char* errorStr;
	const char** includeDirList = new const char*[includeDirs.size()];

	for (size_t i = 0; i < includeDirs.size(); i++)
		includeDirList[i] = includeDirs[i].c_str();

	bool result = BNPreprocessSource(source.c_str(), fileName.c_str(), &outStr, &errorStr,
	                                 includeDirList, includeDirs.size());

	output = outStr;
	errors = errorStr;

	BNFreeString(outStr);
	BNFreeString(errorStr);
	delete[] includeDirList;
	return result;
}
