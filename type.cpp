// Copyright (c) 2015-2020 Vector 35 Inc
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


NameList::NameList(const string& join): m_join(join)
{
}


NameList::NameList(const string& name, const string& join): m_join(join)
{
	if (!name.empty())
		m_name.push_back(name);
}


NameList::NameList(const vector<string>& name, const string& join): m_join(join), m_name(name)
{
}


NameList::NameList(const NameList& name, const string& join): m_join(join), m_name(name.m_name)
{
}

NameList::NameList(const NameList& name): m_join(name.m_join), m_name(name.m_name)
{
}

NameList::~NameList()
{}

NameList& NameList::operator=(const string& name)
{
	m_name = vector<string>{name};
	return *this;
}


NameList& NameList::operator=(const vector<string>& name)
{
	m_name = name;
	return *this;
}


NameList& NameList::operator=(const NameList& name)
{
	m_name = name.m_name;
	return *this;
}


bool NameList::operator==(const NameList& other) const
{
	return m_name == other.m_name;
}


bool NameList::operator!=(const NameList& other) const
{
	return m_name != other.m_name;
}


bool NameList::operator<(const NameList& other) const
{
	return m_name < other.m_name;
}


NameList NameList::operator+(const NameList& other) const
{
	NameList result(*this);
	result.m_name.insert(result.m_name.end(), other.m_name.begin(), other.m_name.end());
	return result;
}


string& NameList::operator[](size_t i)
{
	return m_name[i];
}


const string& NameList::operator[](size_t i) const
{
	return m_name[i];
}


vector<string>::iterator NameList::begin()
{
	return m_name.begin();
}


vector<string>::iterator NameList::end()
{
	return m_name.end();
}


vector<string>::const_iterator NameList::begin() const
{
	return m_name.begin();
}


vector<string>::const_iterator NameList::end() const
{
	return m_name.end();
}


string& NameList::front()
{
	return m_name.front();
}


const string& NameList::front() const
{
	return m_name.front();
}


string& NameList::back()
{
	return m_name.back();
}


const string& NameList::back() const
{
	return m_name.back();
}


void NameList::insert(vector<string>::iterator loc, const string& name)
{
	m_name.insert(loc, name);
}


void NameList::insert(vector<string>::iterator loc, vector<string>::iterator b, vector<string>::iterator e)
{
	m_name.insert(loc, b, e);
}


void NameList::erase(vector<string>::iterator i)
{
	m_name.erase(i);
}


void NameList::clear()
{
	m_name.clear();
}


void NameList::push_back(const string& name)
{
	m_name.push_back(name);
}


size_t NameList::size() const
{
	return m_name.size();
}


size_t NameList::StringSize() const
{
	size_t size = 0;
	for (auto& name : m_name)
		size += name.size() + m_join.size();
	return size - m_join.size();
}


string NameList::GetString() const
{
	bool first = true;
	string out;
	for (auto &name : m_name)
	{
		if (!first)
		{
			out += m_join + name;
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


BNNameList NameList::GetAPIObject() const
{
	BNNameList result;
	result.nameCount = m_name.size();
	result.join = BNAllocString(m_join.c_str());
	result.name = new char*[m_name.size()];
	for (size_t i = 0; i < m_name.size(); i++)
		result.name[i] = BNAllocString(m_name[i].c_str());
	return result;
}


void NameList::FreeAPIObject(BNNameList* name)
{
	for (size_t i = 0; i < name->nameCount; i++)
		BNFreeString(name->name[i]);
	BNFreeString(name->join);
	delete[] name->name;
}


NameList NameList::FromAPIObject(BNNameList* name)
{
	NameList result(name->join);
	for (size_t i = 0; i < name->nameCount; i++)
		result.push_back(name->name[i]);
	return result;
}



QualifiedName::QualifiedName(): NameList("::")
{
}


QualifiedName::QualifiedName(const string& name): NameList(name, "::")
{
}


QualifiedName::QualifiedName(const vector<string>& name): NameList(name, "::")
{
}


QualifiedName::QualifiedName(const QualifiedName& name): NameList(name.m_name, "::")
{
}


QualifiedName::~QualifiedName()
{}


QualifiedName& QualifiedName::operator=(const string& name)
{
	m_name = vector<string>{name};
	m_join = "::";
	return *this;
}


QualifiedName& QualifiedName::operator=(const vector<string>& name)
{
	m_name = name;
	m_join = "::";
	return *this;
}


QualifiedName& QualifiedName::operator=(const QualifiedName& name)
{
	m_name = name.m_name;
	m_join = "::";
	return *this;
}


QualifiedName QualifiedName::operator+(const QualifiedName& other) const
{
	QualifiedName result(*this);
	result.m_join = "::";
	result.m_name.insert(result.m_name.end(), other.m_name.begin(), other.m_name.end());
	return result;
}


BNQualifiedName QualifiedName::GetAPIObject() const
{
	BNQualifiedName result;
	result.nameCount = m_name.size();
	result.join = BNAllocString(m_join.c_str());
	result.name = new char*[m_name.size()];
	for (size_t i = 0; i < m_name.size(); i++)
		result.name[i] = BNAllocString(m_name[i].c_str());
	return result;
}


void QualifiedName::FreeAPIObject(BNQualifiedName* name)
{
	for (size_t i = 0; i < name->nameCount; i++)
		BNFreeString(name->name[i]);
	BNFreeString(name->join);
	delete[] name->name;
}


QualifiedName QualifiedName::FromAPIObject(BNQualifiedName* name)
{
	QualifiedName result;
	for (size_t i = 0; i < name->nameCount; i++)
		result.push_back(name->name[i]);
	return result;
}


NameSpace::NameSpace(): NameList("::")
{
}


NameSpace::NameSpace(const string& name): NameList(name, "::")
{
}


NameSpace::NameSpace(const vector<string>& name): NameList(name, "::")
{
}


NameSpace::NameSpace(const NameSpace& name): NameList(name.m_name, "::")
{
}


NameSpace::~NameSpace()
{}


NameSpace& NameSpace::operator=(const string& name)
{
	m_name = vector<string>{name};
	m_join = "::";
	return *this;
}


NameSpace& NameSpace::operator=(const vector<string>& name)
{
	m_name = name;
	m_join = "::";
	return *this;
}


NameSpace& NameSpace::operator=(const NameSpace& name)
{
	m_name = name.m_name;
	m_join = "::";
	return *this;
}


NameSpace NameSpace::operator+(const NameSpace& other) const
{
	NameSpace result(*this);
	result.m_join = "::";
	result.m_name.insert(result.m_name.end(), other.m_name.begin(), other.m_name.end());
	return result;
}


bool NameSpace::IsDefaultNameSpace() const
{
	return ((GetString() == DEFAULT_INTERNAL_NAMESPACE) || (GetString() == DEFAULT_EXTERNAL_NAMESPACE));
}


BNNameSpace NameSpace::GetAPIObject() const
{
	BNNameSpace result;
	result.nameCount = m_name.size();
	result.join = BNAllocString(m_join.c_str());
	result.name = new char*[m_name.size()];
	for (size_t i = 0; i < m_name.size(); i++)
		result.name[i] = BNAllocString(m_name[i].c_str());
	return result;
}


void NameSpace::FreeAPIObject(BNNameSpace* name)
{
	if (!name)
		return;
	for (size_t i = 0; i < name->nameCount; i++)
		BNFreeString(name->name[i]);
	BNFreeString(name->join);
	delete[] name->name;
}


NameSpace NameSpace::FromAPIObject(const BNNameSpace* name)
{
	NameSpace result;
	if (!name)
		return result;
	for (size_t i = 0; i < name->nameCount; i++)
		result.push_back(name->name[i]);
	return result;
}


Type::Type(BNType* type)
{
	m_object = type;
}

bool Type::operator==(const Type& other)
{
	return BNTypesEqual(m_object, other.m_object);
}


bool Type::operator!=(const Type& other)
{
	return BNTypesNotEqual(m_object, other.m_object);
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


Confidence<bool> Type::IsSigned() const
{
	BNBoolWithConfidence result = BNIsTypeSigned(m_object);
	return Confidence<bool>(result.value, result.confidence);
}


Confidence<bool> Type::IsConst() const
{
	BNBoolWithConfidence result = BNIsTypeConst(m_object);
	return Confidence<bool>(result.value, result.confidence);
}


Confidence<BNMemberScope> Type::GetScope() const
{
	BNMemberScopeWithConfidence result = BNTypeGetMemberScope(m_object);
	return Confidence<BNMemberScope>(result.value, result.confidence);
}


Confidence<BNMemberAccess> Type::GetAccess() const
{
	BNMemberAccessWithConfidence result = BNTypeGetMemberAccess(m_object);
	return Confidence<BNMemberAccess>(result.value, result.confidence);
}


Confidence<Ref<Type>> Type::GetChildType() const
{
	BNTypeWithConfidence type = BNGetChildType(m_object);
	if (type.type)
		return Confidence<Ref<Type>>(new Type(type.type), type.confidence);
	return nullptr;
}


Confidence<Ref<CallingConvention>> Type::GetCallingConvention() const
{
	BNCallingConventionWithConfidence cc = BNGetTypeCallingConvention(m_object);
	if (cc.convention)
		return Confidence<Ref<CallingConvention>>(new CoreCallingConvention(cc.convention), cc.confidence);
	return nullptr;
}


vector<FunctionParameter> Type::GetParameters() const
{
	size_t count;
	BNFunctionParameter* types = BNGetTypeParameters(m_object, &count);

	vector<FunctionParameter> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		FunctionParameter param;
		param.name = types[i].name;
		param.type = Confidence<Ref<Type>>(new Type(BNNewTypeReference(types[i].type)), types[i].typeConfidence);
		param.defaultLocation = types[i].defaultLocation;
		param.location.type = types[i].location.type;
		param.location.index = types[i].location.index;
		param.location.storage = types[i].location.storage;
		result.push_back(param);
	}

	BNFreeTypeParameterList(types, count);
	return result;
}


Confidence<bool> Type::HasVariableArguments() const
{
	BNBoolWithConfidence result = BNTypeHasVariableArguments(m_object);
	return Confidence<bool>(result.value, result.confidence);
}


Confidence<bool> Type::CanReturn() const
{
	BNBoolWithConfidence result = BNFunctionTypeCanReturn(m_object);
	return Confidence<bool>(result.value, result.confidence);
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


Ref<NamedTypeReference> Type::GetNamedTypeReference() const
{
	BNNamedTypeReference* ref = BNGetTypeNamedTypeReference(m_object);
	if (ref)
		return new NamedTypeReference(ref);
	return nullptr;
}


uint64_t Type::GetElementCount() const
{
	return BNGetTypeElementCount(m_object);
}


uint64_t Type::GetOffset() const
{
	return BNGetTypeOffset(m_object);
}


Confidence<int64_t> Type::GetStackAdjustment() const
{
	BNOffsetWithConfidence result = BNGetTypeStackAdjustment(m_object);
	return Confidence<int64_t>(result.value, result.confidence);
}


string Type::GetString(Platform* platform) const
{
	char* str = BNGetTypeString(m_object, platform ? platform->GetObject() : nullptr);
	string result = str;
	BNFreeString(str);
	return result;
}


string Type::GetTypeAndName(const QualifiedName& nameList) const
{
	BNQualifiedName name = nameList.GetAPIObject();
	char* outName = BNGetTypeAndName(m_object, &name);
	QualifiedName::FreeAPIObject(&name);
	return outName;
}

string Type::GetStringBeforeName(Platform* platform) const
{
	char* str = BNGetTypeStringBeforeName(m_object, platform ? platform->GetObject() : nullptr);
	string result = str;
	BNFreeString(str);
	return result;
}


string Type::GetStringAfterName(Platform* platform) const
{
	char* str = BNGetTypeStringAfterName(m_object, platform ? platform->GetObject() : nullptr);
	string result = str;
	BNFreeString(str);
	return result;
}


vector<InstructionTextToken> Type::GetTokens(Platform* platform, uint8_t baseConfidence) const
{
	size_t count;
	BNInstructionTextToken* tokens = BNGetTypeTokens(m_object,
		platform ? platform->GetObject() : nullptr, baseConfidence, &count);

	return InstructionTextToken::ConvertAndFreeInstructionTextTokenList(tokens, count);
}


vector<InstructionTextToken> Type::GetTokensBeforeName(Platform* platform, uint8_t baseConfidence) const
{
	size_t count;
	BNInstructionTextToken* tokens = BNGetTypeTokensBeforeName(m_object,
		platform ? platform->GetObject() : nullptr, baseConfidence, &count);
	return InstructionTextToken::ConvertAndFreeInstructionTextTokenList(tokens, count);
}


vector<InstructionTextToken> Type::GetTokensAfterName(Platform* platform, uint8_t baseConfidence) const
{
	size_t count;
	BNInstructionTextToken* tokens = BNGetTypeTokensAfterName(m_object,
		platform ? platform->GetObject() : nullptr, baseConfidence, &count);

	return InstructionTextToken::ConvertAndFreeInstructionTextTokenList(tokens, count);
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


Ref<Type> Type::IntegerType(size_t width, const Confidence<bool>& sign, const string& altName)
{
	BNBoolWithConfidence bc;
	bc.value = sign.GetValue();
	bc.confidence = sign.GetConfidence();
	return new Type(BNCreateIntegerType(width, &bc, altName.c_str()));
}


Ref<Type> Type::FloatType(size_t width, const string& altName)
{
	return new Type(BNCreateFloatType(width, altName.c_str()));
}


Ref<Type> Type::StructureType(Structure* strct)
{
	return new Type(BNCreateStructureType(strct->GetObject()));
}


Ref<Type> Type::NamedType(NamedTypeReference* ref, size_t width, size_t align)
{
	return new Type(BNCreateNamedTypeReference(ref->GetObject(), width, align));
}


Ref<Type> Type::NamedType(const QualifiedName& name, Type* type)
{
	return NamedType("", name, type);
}


Ref<Type> Type::NamedType(const string& id, const QualifiedName& name, Type* type)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	BNType* coreObj = BNCreateNamedTypeReferenceFromTypeAndId(id.c_str(), &nameObj,
		type ? type->GetObject() : nullptr);
	QualifiedName::FreeAPIObject(&nameObj);
	return coreObj ? new Type(coreObj) : nullptr;
}


Ref<Type> Type::NamedType(BinaryView* view, const QualifiedName& name)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	BNType* coreObj = BNCreateNamedTypeReferenceFromType(view->GetObject(), &nameObj);
	QualifiedName::FreeAPIObject(&nameObj);
	return coreObj ? new Type(coreObj) : nullptr;
}


Ref<Type> Type::EnumerationType(Architecture* arch, Enumeration* enm, size_t width, bool isSigned)
{
	return new Type(BNCreateEnumerationType(arch->GetObject(), enm->GetObject(), width, isSigned));
}


Ref<Type> Type::PointerType(Architecture* arch, const Confidence<Ref<Type>>& type,
	const Confidence<bool>& cnst, const Confidence<bool>& vltl, BNReferenceType refType)
{
	BNTypeWithConfidence typeConf;
	typeConf.type = type->GetObject();
	typeConf.confidence = type.GetConfidence();

	BNBoolWithConfidence cnstConf;
	cnstConf.value = cnst.GetValue();
	cnstConf.confidence = cnst.GetConfidence();

	BNBoolWithConfidence vltlConf;
	vltlConf.value = vltl.GetValue();
	vltlConf.confidence = vltl.GetConfidence();

	return new Type(BNCreatePointerType(arch->GetObject(), &typeConf, &cnstConf, &vltlConf, refType));
}


Ref<Type> Type::PointerType(size_t width, const Confidence<Ref<Type>>& type,
	const Confidence<bool>& cnst, const Confidence<bool>& vltl, BNReferenceType refType)
{
	BNTypeWithConfidence typeConf;
	typeConf.type = type->GetObject();
	typeConf.confidence = type.GetConfidence();

	BNBoolWithConfidence cnstConf;
	cnstConf.value = cnst.GetValue();
	cnstConf.confidence = cnst.GetConfidence();

	BNBoolWithConfidence vltlConf;
	vltlConf.value = vltl.GetValue();
	vltlConf.confidence = vltl.GetConfidence();

	return new Type(BNCreatePointerTypeOfWidth(width, &typeConf, &cnstConf, &vltlConf, refType));
}


Ref<Type> Type::ArrayType(const Confidence<Ref<Type>>& type, uint64_t elem)
{
	BNTypeWithConfidence typeConf;
	typeConf.type = type->GetObject();
	typeConf.confidence = type.GetConfidence();
	return new Type(BNCreateArrayType(&typeConf, elem));
}


Ref<Type> Type::FunctionType(const Confidence<Ref<Type>>& returnValue,
	const Confidence<Ref<CallingConvention>>& callingConvention,
	const std::vector<FunctionParameter>& params, const Confidence<bool>& varArg,
	const Confidence<int64_t>& stackAdjust)
{
	BNTypeWithConfidence returnValueConf;
	returnValueConf.type = returnValue->GetObject();
	returnValueConf.confidence = returnValue.GetConfidence();

	BNCallingConventionWithConfidence callingConventionConf;
	callingConventionConf.convention = callingConvention ? callingConvention->GetObject() : nullptr;
	callingConventionConf.confidence = callingConvention.GetConfidence();

	BNFunctionParameter* paramArray = new BNFunctionParameter[params.size()];
	for (size_t i = 0; i < params.size(); i++)
	{
		paramArray[i].name = (char*)params[i].name.c_str();
		paramArray[i].type = params[i].type->GetObject();
		paramArray[i].typeConfidence = params[i].type.GetConfidence();
		paramArray[i].defaultLocation = params[i].defaultLocation;
		paramArray[i].location.type = params[i].location.type;
		paramArray[i].location.index = params[i].location.index;
		paramArray[i].location.storage = params[i].location.storage;
	}

	BNBoolWithConfidence varArgConf;
	varArgConf.value = varArg.GetValue();
	varArgConf.confidence = varArg.GetConfidence();

	BNOffsetWithConfidence stackAdjustConf;
	stackAdjustConf.value = stackAdjust.GetValue();
	stackAdjustConf.confidence = stackAdjust.GetConfidence();

	Type* type = new Type(BNCreateFunctionType(&returnValueConf, &callingConventionConf,
		paramArray, params.size(), &varArgConf, &stackAdjustConf));
	delete[] paramArray;
	return type;
}

BNIntegerDisplayType Type::GetIntegerTypeDisplayType() const
{
	return BNGetIntegerTypeDisplayType(m_object);
}

string Type::GenerateAutoTypeId(const string& source, const QualifiedName& name)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	char* str = BNGenerateAutoTypeId(source.c_str(), &nameObj);
	string result = str;
	QualifiedName::FreeAPIObject(&nameObj);
	BNFreeString(str);
	return result;
}


string Type::GenerateAutoDemangledTypeId(const QualifiedName& name)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	char* str = BNGenerateAutoDemangledTypeId(&nameObj);
	string result = str;
	QualifiedName::FreeAPIObject(&nameObj);
	BNFreeString(str);
	return result;
}


string Type::GetAutoDemangledTypeIdSource()
{
	char* str = BNGetAutoDemangledTypeIdSource();
	string result = str;
	BNFreeString(str);
	return result;
}


string Type::GenerateAutoDebugTypeId(const QualifiedName& name)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	char* str = BNGenerateAutoDebugTypeId(&nameObj);
	string result = str;
	QualifiedName::FreeAPIObject(&nameObj);
	BNFreeString(str);
	return result;
}


string Type::GetAutoDebugTypeIdSource()
{
	char* str = BNGetAutoDebugTypeIdSource();
	string result = str;
	BNFreeString(str);
	return result;
}


bool Type::IsReferenceOfType(BNNamedTypeReferenceClass refType)
{
	return (GetClass() == NamedTypeReferenceClass) && (GetNamedTypeReference()->GetTypeClass() == refType);
}


QualifiedName Type::GetTypeName() const
{
	BNQualifiedName name = BNTypeGetTypeName(m_object);
	QualifiedName result = QualifiedName::FromAPIObject(&name);
	BNFreeQualifiedName(&name);
	return result;
}


Confidence<Ref<Type>> Type::WithConfidence(uint8_t conf)
{
	return Confidence<Ref<Type>>(this, conf);
}


QualifiedName Type::GetStructureName() const
{
	BNQualifiedName name = BNTypeGetStructureName(m_object);
	QualifiedName result = QualifiedName::FromAPIObject(&name);
	BNFreeQualifiedName(&name);
	return result;
}


Ref<NamedTypeReference> Type::GetRegisteredName() const
{
	BNNamedTypeReference* name = BNGetRegisteredTypeName(m_object);
	if (!name)
		return nullptr;
	return new NamedTypeReference(name);
}


Ref<Type> Type::WithReplacedStructure(Structure* from, Structure* to)
{
	BNType* result = BNTypeWithReplacedStructure(m_object, from->GetObject(), to->GetObject());
	if (result == m_object)
	{
		BNFreeType(result);
		return this;
	}
	return new Type(result);
}


Ref<Type> Type::WithReplacedEnumeration(Enumeration* from, Enumeration* to)
{
	BNType* result = BNTypeWithReplacedEnumeration(m_object, from->GetObject(), to->GetObject());
	if (result == m_object)
	{
		BNFreeType(result);
		return this;
	}
	return new Type(result);
}


Ref<Type> Type::WithReplacedNamedTypeReference(NamedTypeReference* from, NamedTypeReference* to)
{
	BNType* result = BNTypeWithReplacedNamedTypeReference(m_object, from->GetObject(), to->GetObject());
	if (result == m_object)
	{
		BNFreeType(result);
		return this;
	}
	return new Type(result);
}


TypeBuilder::TypeBuilder()
{
	m_object = BNCreateVoidTypeBuilder();
}


TypeBuilder::TypeBuilder(BNTypeBuilder* type)
{
	m_object = type;
}


TypeBuilder::TypeBuilder(const TypeBuilder& type)
{
	m_object = BNDuplicateTypeBuilder(type.m_object);
}


TypeBuilder::TypeBuilder(TypeBuilder&& type)
{
	m_object = type.m_object;
	type.m_object = BNCreateVoidTypeBuilder();
}


TypeBuilder::TypeBuilder(Type* type)
{
	m_object = BNCreateTypeBuilderFromType(type->GetObject());
}


TypeBuilder& TypeBuilder::operator=(const TypeBuilder& type)
{
	if (this != &type)
	{
		BNFreeTypeBuilder(m_object);
		m_object = BNDuplicateTypeBuilder(type.m_object);
	}
	return *this;
}


TypeBuilder& TypeBuilder::operator=(TypeBuilder&& type)
{
	std::swap(m_object, type.m_object);
	return *this;
}


TypeBuilder& TypeBuilder::operator=(Type* type)
{
	BNFreeTypeBuilder(m_object);
	m_object = BNCreateTypeBuilderFromType(type->GetObject());
	return *this;
}


Ref<Type> TypeBuilder::Finalize()
{
	return new Type(BNFinalizeTypeBuilder(m_object));
}


BNTypeClass TypeBuilder::GetClass() const
{
	return BNGetTypeBuilderClass(m_object);
}


uint64_t TypeBuilder::GetWidth() const
{
	return BNGetTypeBuilderWidth(m_object);
}


size_t TypeBuilder::GetAlignment() const
{
	return BNGetTypeBuilderAlignment(m_object);
}


Confidence<bool> TypeBuilder::IsSigned() const
{
	BNBoolWithConfidence result = BNIsTypeBuilderSigned(m_object);
	return Confidence<bool>(result.value, result.confidence);
}


Confidence<bool> TypeBuilder::IsConst() const
{
	BNBoolWithConfidence result = BNIsTypeBuilderConst(m_object);
	return Confidence<bool>(result.value, result.confidence);
}

void TypeBuilder::SetIntegerTypeDisplayType(BNIntegerDisplayType displayType)
{
	BNSetIntegerTypeDisplayType(m_object, displayType);
}

Confidence<BNMemberScope> TypeBuilder::GetScope() const
{
	BNMemberScopeWithConfidence result = BNTypeBuilderGetMemberScope(m_object);
	return Confidence<BNMemberScope>(result.value, result.confidence);
}


TypeBuilder& TypeBuilder::SetScope(const Confidence<BNMemberScope>& scope)
{
	BNMemberScopeWithConfidence mc;
	mc.value = scope.GetValue();
	mc.confidence = scope.GetConfidence();
	BNTypeBuilderSetMemberScope(m_object, &mc);
	return *this;
}


Confidence<BNMemberAccess> TypeBuilder::GetAccess() const
{
	BNMemberAccessWithConfidence result = BNTypeBuilderGetMemberAccess(m_object);
	return Confidence<BNMemberAccess>(result.value, result.confidence);
}


TypeBuilder& TypeBuilder::SetAccess(const Confidence<BNMemberAccess>& access)
{
	BNMemberAccessWithConfidence mc;
	mc.value = access.GetValue();
	mc.confidence = access.GetConfidence();
	BNTypeBuilderSetMemberAccess(m_object, &mc);
	return *this;
}


TypeBuilder& TypeBuilder::SetConst(const Confidence<bool>& cnst)
{
	BNBoolWithConfidence bc;
	bc.value = cnst.GetValue();
	bc.confidence = cnst.GetConfidence();
	BNTypeBuilderSetConst(m_object, &bc);
	return *this;
}


TypeBuilder& TypeBuilder::SetVolatile(const Confidence<bool>& vltl)
{
	BNBoolWithConfidence bc;
	bc.value = vltl.GetValue();
	bc.confidence = vltl.GetConfidence();
	BNTypeBuilderSetVolatile(m_object, &bc);
	return *this;
}


Confidence<Ref<Type>> TypeBuilder::GetChildType() const
{
	BNTypeWithConfidence type = BNGetTypeBuilderChildType(m_object);
	if (type.type)
		return Confidence<Ref<Type>>(new Type(type.type), type.confidence);
	return nullptr;
}


Confidence<Ref<CallingConvention>> TypeBuilder::GetCallingConvention() const
{
	BNCallingConventionWithConfidence cc = BNGetTypeBuilderCallingConvention(m_object);
	if (cc.convention)
		return Confidence<Ref<CallingConvention>>(new CoreCallingConvention(cc.convention), cc.confidence);
	return nullptr;
}


vector<FunctionParameter> TypeBuilder::GetParameters() const
{
	size_t count;
	BNFunctionParameter* types = BNGetTypeBuilderParameters(m_object, &count);

	vector<FunctionParameter> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		FunctionParameter param;
		param.name = types[i].name;
		param.type = Confidence<Ref<Type>>(new Type(BNNewTypeReference(types[i].type)), types[i].typeConfidence);
		param.defaultLocation = types[i].defaultLocation;
		param.location.type = types[i].location.type;
		param.location.index = types[i].location.index;
		param.location.storage = types[i].location.storage;
		result.push_back(param);
	}

	BNFreeTypeParameterList(types, count);
	return result;
}


Confidence<bool> TypeBuilder::HasVariableArguments() const
{
	BNBoolWithConfidence result = BNTypeBuilderHasVariableArguments(m_object);
	return Confidence<bool>(result.value, result.confidence);
}


Confidence<bool> TypeBuilder::CanReturn() const
{
	BNBoolWithConfidence result = BNFunctionTypeBuilderCanReturn(m_object);
	return Confidence<bool>(result.value, result.confidence);
}


Ref<Structure> TypeBuilder::GetStructure() const
{
	BNStructure* s = BNGetTypeBuilderStructure(m_object);
	if (s)
		return new Structure(s);
	return nullptr;
}


Ref<Enumeration> TypeBuilder::GetEnumeration() const
{
	BNEnumeration* e = BNGetTypeBuilderEnumeration(m_object);
	if (e)
		return new Enumeration(e);
	return nullptr;
}


Ref<NamedTypeReference> TypeBuilder::GetNamedTypeReference() const
{
	BNNamedTypeReference* ref = BNGetTypeBuilderNamedTypeReference(m_object);
	if (ref)
		return new NamedTypeReference(ref);
	return nullptr;
}


uint64_t TypeBuilder::GetElementCount() const
{
	return BNGetTypeBuilderElementCount(m_object);
}


uint64_t TypeBuilder::GetOffset() const
{
	return BNGetTypeBuilderOffset(m_object);
}


Confidence<int64_t> TypeBuilder::GetStackAdjustment() const
{
	BNOffsetWithConfidence result = BNGetTypeBuilderStackAdjustment(m_object);
	return Confidence<int64_t>(result.value, result.confidence);
}


string TypeBuilder::GetString(Platform* platform) const
{
	char* str = BNGetTypeBuilderString(m_object, platform ? platform->GetObject() : nullptr);
	string result = str;
	BNFreeString(str);
	return result;
}


string TypeBuilder::GetTypeAndName(const QualifiedName& nameList) const
{
	BNQualifiedName name = nameList.GetAPIObject();
	char* outName = BNGetTypeBuilderTypeAndName(m_object, &name);
	QualifiedName::FreeAPIObject(&name);
	return outName;
}

string TypeBuilder::GetStringBeforeName(Platform* platform) const
{
	char* str = BNGetTypeBuilderStringBeforeName(m_object, platform ? platform->GetObject() : nullptr);
	string result = str;
	BNFreeString(str);
	return result;
}


string TypeBuilder::GetStringAfterName(Platform* platform) const
{
	char* str = BNGetTypeBuilderStringAfterName(m_object, platform ? platform->GetObject() : nullptr);
	string result = str;
	BNFreeString(str);
	return result;
}


vector<InstructionTextToken> TypeBuilder::GetTokens(Platform* platform, uint8_t baseConfidence) const
{
	size_t count;
	BNInstructionTextToken* tokens = BNGetTypeBuilderTokens(m_object,
		platform ? platform->GetObject() : nullptr, baseConfidence, &count);

	return InstructionTextToken::ConvertAndFreeInstructionTextTokenList(tokens, count);
}


vector<InstructionTextToken> TypeBuilder::GetTokensBeforeName(Platform* platform, uint8_t baseConfidence) const
{
	size_t count;
	BNInstructionTextToken* tokens = BNGetTypeBuilderTokensBeforeName(m_object,
		platform ? platform->GetObject() : nullptr, baseConfidence, &count);
	return InstructionTextToken::ConvertAndFreeInstructionTextTokenList(tokens, count);
}


vector<InstructionTextToken> TypeBuilder::GetTokensAfterName(Platform* platform, uint8_t baseConfidence) const
{
	size_t count;
	BNInstructionTextToken* tokens = BNGetTypeBuilderTokensAfterName(m_object,
		platform ? platform->GetObject() : nullptr, baseConfidence, &count);

	return InstructionTextToken::ConvertAndFreeInstructionTextTokenList(tokens, count);
}


TypeBuilder TypeBuilder::VoidType()
{
	return TypeBuilder(BNCreateVoidTypeBuilder());
}


TypeBuilder TypeBuilder::BoolType()
{
	return TypeBuilder(BNCreateBoolTypeBuilder());
}


TypeBuilder TypeBuilder::IntegerType(size_t width, const Confidence<bool>& sign, const string& altName)
{
	BNBoolWithConfidence bc;
	bc.value = sign.GetValue();
	bc.confidence = sign.GetConfidence();
	return TypeBuilder(BNCreateIntegerTypeBuilder(width, &bc, altName.c_str()));
}


TypeBuilder TypeBuilder::FloatType(size_t width, const string& altName)
{
	return TypeBuilder(BNCreateFloatTypeBuilder(width, altName.c_str()));
}


TypeBuilder TypeBuilder::StructureType(Structure* strct)
{
	return TypeBuilder(BNCreateStructureTypeBuilder(strct->GetObject()));
}


TypeBuilder TypeBuilder::NamedType(NamedTypeReference* ref, size_t width, size_t align)
{
	return TypeBuilder(BNCreateNamedTypeReferenceBuilder(ref->GetObject(), width, align));
}


TypeBuilder TypeBuilder::NamedType(const QualifiedName& name, Type* type)
{
	return NamedType("", name, type);
}


TypeBuilder TypeBuilder::NamedType(const string& id, const QualifiedName& name, Type* type)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	BNTypeBuilder* coreObj = BNCreateNamedTypeReferenceBuilderFromTypeAndId(id.c_str(), &nameObj,
		type ? type->GetObject() : nullptr);
	QualifiedName::FreeAPIObject(&nameObj);
	return coreObj ? TypeBuilder(coreObj) : VoidType();
}


TypeBuilder TypeBuilder::NamedType(BinaryView* view, const QualifiedName& name)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	BNTypeBuilder* coreObj = BNCreateNamedTypeReferenceBuilderFromType(view->GetObject(), &nameObj);
	QualifiedName::FreeAPIObject(&nameObj);
	return coreObj ? TypeBuilder(coreObj) : VoidType();
}


TypeBuilder TypeBuilder::EnumerationType(Architecture* arch, Enumeration* enm, size_t width, bool isSigned)
{
	return TypeBuilder(BNCreateEnumerationTypeBuilder(arch->GetObject(), enm->GetObject(), width, isSigned));
}


TypeBuilder TypeBuilder::PointerType(Architecture* arch, const Confidence<Ref<Type>>& type,
	const Confidence<bool>& cnst, const Confidence<bool>& vltl, BNReferenceType refType)
{
	BNTypeWithConfidence typeConf;
	typeConf.type = type->GetObject();
	typeConf.confidence = type.GetConfidence();

	BNBoolWithConfidence cnstConf;
	cnstConf.value = cnst.GetValue();
	cnstConf.confidence = cnst.GetConfidence();

	BNBoolWithConfidence vltlConf;
	vltlConf.value = vltl.GetValue();
	vltlConf.confidence = vltl.GetConfidence();

	return TypeBuilder(BNCreatePointerTypeBuilder(arch->GetObject(), &typeConf, &cnstConf, &vltlConf, refType));
}


TypeBuilder TypeBuilder::PointerType(size_t width, const Confidence<Ref<Type>>& type,
	const Confidence<bool>& cnst, const Confidence<bool>& vltl, BNReferenceType refType)
{
	BNTypeWithConfidence typeConf;
	typeConf.type = type->GetObject();
	typeConf.confidence = type.GetConfidence();

	BNBoolWithConfidence cnstConf;
	cnstConf.value = cnst.GetValue();
	cnstConf.confidence = cnst.GetConfidence();

	BNBoolWithConfidence vltlConf;
	vltlConf.value = vltl.GetValue();
	vltlConf.confidence = vltl.GetConfidence();

	return TypeBuilder(BNCreatePointerTypeBuilderOfWidth(width, &typeConf, &cnstConf, &vltlConf, refType));
}


TypeBuilder TypeBuilder::ArrayType(const Confidence<Ref<Type>>& type, uint64_t elem)
{
	BNTypeWithConfidence typeConf;
	typeConf.type = type->GetObject();
	typeConf.confidence = type.GetConfidence();
	return TypeBuilder(BNCreateArrayTypeBuilder(&typeConf, elem));
}


TypeBuilder TypeBuilder::FunctionType(const Confidence<Ref<Type>>& returnValue,
	const Confidence<Ref<CallingConvention>>& callingConvention,
	const std::vector<FunctionParameter>& params, const Confidence<bool>& varArg,
	const Confidence<int64_t>& stackAdjust)
{
	BNTypeWithConfidence returnValueConf;
	returnValueConf.type = returnValue->GetObject();
	returnValueConf.confidence = returnValue.GetConfidence();

	BNCallingConventionWithConfidence callingConventionConf;
	callingConventionConf.convention = callingConvention ? callingConvention->GetObject() : nullptr;
	callingConventionConf.confidence = callingConvention.GetConfidence();

	BNFunctionParameter* paramArray = new BNFunctionParameter[params.size()];
	for (size_t i = 0; i < params.size(); i++)
	{
		paramArray[i].name = (char*)params[i].name.c_str();
		paramArray[i].type = params[i].type->GetObject();
		paramArray[i].typeConfidence = params[i].type.GetConfidence();
		paramArray[i].defaultLocation = params[i].defaultLocation;
		paramArray[i].location.type = params[i].location.type;
		paramArray[i].location.index = params[i].location.index;
		paramArray[i].location.storage = params[i].location.storage;
	}

	BNBoolWithConfidence varArgConf;
	varArgConf.value = varArg.GetValue();
	varArgConf.confidence = varArg.GetConfidence();

	BNOffsetWithConfidence stackAdjustConf;
	stackAdjustConf.value = stackAdjust.GetValue();
	stackAdjustConf.confidence = stackAdjust.GetConfidence();

	TypeBuilder type(BNCreateFunctionTypeBuilder(&returnValueConf, &callingConventionConf,
		paramArray, params.size(), &varArgConf, &stackAdjustConf));
	delete[] paramArray;
	return type;
}


TypeBuilder& TypeBuilder::SetFunctionCanReturn(const Confidence<bool>& canReturn)
{
	BNBoolWithConfidence bc;
	bc.value = canReturn.GetValue();
	bc.confidence = canReturn.GetConfidence();
	BNSetFunctionTypeBuilderCanReturn(m_object, &bc);
	return *this;
}


bool TypeBuilder::IsReferenceOfType(BNNamedTypeReferenceClass refType)
{
	return (GetClass() == NamedTypeReferenceClass) && (GetNamedTypeReference()->GetTypeClass() == refType);
}


QualifiedName TypeBuilder::GetTypeName() const
{
	BNQualifiedName name = BNTypeBuilderGetTypeName(m_object);
	QualifiedName result = QualifiedName::FromAPIObject(&name);
	BNFreeQualifiedName(&name);
	return result;
}


TypeBuilder& TypeBuilder::SetTypeName(const QualifiedName& names)
{
	BNQualifiedName nameObj = names.GetAPIObject();
	BNTypeBuilderSetTypeName(m_object, &nameObj);
	QualifiedName::FreeAPIObject(&nameObj);
	return *this;
}


QualifiedName TypeBuilder::GetStructureName() const
{
	BNQualifiedName name = BNTypeBuilderGetStructureName(m_object);
	QualifiedName result = QualifiedName::FromAPIObject(&name);
	BNFreeQualifiedName(&name);
	return result;
}


NamedTypeReference::NamedTypeReference(BNNamedTypeReference* nt)
{
	m_object = nt;
}


NamedTypeReference::NamedTypeReference(BNNamedTypeReferenceClass cls, const string& id, const QualifiedName& names)
{
	BNQualifiedName nameObj = names.GetAPIObject();
	m_object = BNCreateNamedType(cls, id.c_str(), &nameObj);
	QualifiedName::FreeAPIObject(&nameObj);
}


BNNamedTypeReferenceClass NamedTypeReference::GetTypeClass() const
{
	return BNGetTypeReferenceClass(m_object);
}


string NamedTypeReference::GetTypeId() const
{
	char* str = BNGetTypeReferenceId(m_object);
	string result = str;
	BNFreeString(str);
	return result;
}


QualifiedName NamedTypeReference::GetName() const
{
	BNQualifiedName name = BNGetTypeReferenceName(m_object);
	QualifiedName result = QualifiedName::FromAPIObject(&name);
	BNFreeQualifiedName(&name);
	return result;
}


Ref<NamedTypeReference> NamedTypeReference::GenerateAutoTypeReference(BNNamedTypeReferenceClass cls,
	const string& source, const QualifiedName& name)
{
	string id = Type::GenerateAutoTypeId(source, name);
	return new NamedTypeReference(cls, id, name);
}


Ref<NamedTypeReference> NamedTypeReference::GenerateAutoDemangledTypeReference(BNNamedTypeReferenceClass cls,
	const QualifiedName& name)
{
	string id = Type::GenerateAutoDemangledTypeId(name);
	return new NamedTypeReference(cls, id, name);
}


Ref<NamedTypeReference> NamedTypeReference::GenerateAutoDebugTypeReference(BNNamedTypeReferenceClass cls,
	const QualifiedName& name)
{
	string id = Type::GenerateAutoDebugTypeId(name);
	return new NamedTypeReference(cls, id, name);
}


Structure::Structure(BNStructure* s)
{
	m_object = s;
}


vector<StructureMember> Structure::GetMembers() const
{
	size_t count;
	BNStructureMember* members = BNGetStructureMembers(m_object, &count);

	vector<StructureMember> result;
	result.reserve(count);
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


bool Structure::GetMemberByName(const string& name, StructureMember& result) const
{
	BNStructureMember* member = BNGetStructureMemberByName(m_object, name.c_str());
	if (member)
	{
		result.type = new Type(BNNewTypeReference(member->type));
		result.name = member->name;
		result.offset = member->offset;
		BNFreeStructureMember(member);
		return true;
	}
	return false;
}


bool Structure::GetMemberAtOffset(int64_t offset, StructureMember& result) const
{
	size_t i;
	return GetMemberAtOffset(offset, result, i);
}


bool Structure::GetMemberAtOffset(int64_t offset, StructureMember& result, size_t& idx) const
{
	BNStructureMember* member = BNGetStructureMemberAtOffset(m_object, offset, &idx);
	if (member)
	{
		result.type = new Type(BNNewTypeReference(member->type));
		result.name = member->name;
		result.offset = member->offset;
		BNFreeStructureMember(member);
		return true;
	}
	return false;
}


uint64_t Structure::GetWidth() const
{
	return BNGetStructureWidth(m_object);
}


size_t Structure::GetAlignment() const
{
	return BNGetStructureAlignment(m_object);
}


bool Structure::IsPacked() const
{
	return BNIsStructurePacked(m_object);
}


bool Structure::IsUnion() const
{
	return BNIsStructureUnion(m_object);
}


BNStructureType Structure::GetStructureType() const
{
	return BNGetStructureType(m_object);
}


Ref<Structure> Structure::WithReplacedStructure(Structure* from, Structure* to)
{
	BNStructure* result = BNStructureWithReplacedStructure(m_object, from->GetObject(), to->GetObject());
	if (result == m_object)
	{
		BNFreeStructure(result);
		return this;
	}
	return new Structure(result);
}


Ref<Structure> Structure::WithReplacedEnumeration(Enumeration* from, Enumeration* to)
{
	BNStructure* result = BNStructureWithReplacedEnumeration(m_object, from->GetObject(), to->GetObject());
	if (result == m_object)
	{
		BNFreeStructure(result);
		return this;
	}
	return new Structure(result);
}


Ref<Structure> Structure::WithReplacedNamedTypeReference(NamedTypeReference* from, NamedTypeReference* to)
{
	BNStructure* result = BNStructureWithReplacedNamedTypeReference(m_object, from->GetObject(), to->GetObject());
	if (result == m_object)
	{
		BNFreeStructure(result);
		return this;
	}
	return new Structure(result);
}


StructureBuilder::StructureBuilder()
{
	m_object = BNCreateStructureBuilder();
}


StructureBuilder::StructureBuilder(BNStructureBuilder* s)
{
	m_object = s;
}


StructureBuilder::StructureBuilder(BNStructureType type, bool packed)
{
	m_object = BNCreateStructureBuilderWithOptions(type, packed);
}


StructureBuilder::StructureBuilder(const StructureBuilder& s)
{
	m_object = BNDuplicateStructureBuilder(s.m_object);
}


StructureBuilder::StructureBuilder(StructureBuilder&& s)
{
	m_object = s.m_object;
	s.m_object = BNCreateStructureBuilder();
}


StructureBuilder::StructureBuilder(Structure* s)
{
	m_object = BNCreateStructureBuilderFromStructure(s->GetObject());
}


StructureBuilder::~StructureBuilder()
{
	BNFreeStructureBuilder(m_object);
}


StructureBuilder& StructureBuilder::operator=(const StructureBuilder& s)
{
	if (this != &s)
	{
		BNFreeStructureBuilder(m_object);
		m_object = BNDuplicateStructureBuilder(s.m_object);
	}
	return *this;
}


StructureBuilder& StructureBuilder::operator=(StructureBuilder&& s)
{
	if (this != &s)
		std::swap(m_object, s.m_object);
	return *this;
}


StructureBuilder& StructureBuilder::operator=(Structure* s)
{
	BNFreeStructureBuilder(m_object);
	m_object = BNCreateStructureBuilderFromStructure(s->GetObject());
	return *this;
}


Ref<Structure> StructureBuilder::Finalize() const
{
	return new Structure(BNFinalizeStructureBuilder(m_object));
}


vector<StructureMember> StructureBuilder::GetMembers() const
{
	size_t count;
	BNStructureMember* members = BNGetStructureBuilderMembers(m_object, &count);

	vector<StructureMember> result;
	result.reserve(count);
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


bool StructureBuilder::GetMemberByName(const string& name, StructureMember& result) const
{
	BNStructureMember* member = BNGetStructureBuilderMemberByName(m_object, name.c_str());
	if (member)
	{
		result.type = new Type(BNNewTypeReference(member->type));
		result.name = member->name;
		result.offset = member->offset;
		BNFreeStructureMember(member);
		return true;
	}
	return false;
}


bool StructureBuilder::GetMemberAtOffset(int64_t offset, StructureMember& result) const
{
	size_t i;
	return GetMemberAtOffset(offset, result, i);
}


bool StructureBuilder::GetMemberAtOffset(int64_t offset, StructureMember& result, size_t& idx) const
{
	BNStructureMember* member = BNGetStructureBuilderMemberAtOffset(m_object, offset, &idx);
	if (member)
	{
		result.type = new Type(BNNewTypeReference(member->type));
		result.name = member->name;
		result.offset = member->offset;
		BNFreeStructureMember(member);
		return true;
	}
	return false;
}


uint64_t StructureBuilder::GetWidth() const
{
	return BNGetStructureBuilderWidth(m_object);
}


StructureBuilder& StructureBuilder::SetWidth(size_t width)
{
	BNSetStructureBuilderWidth(m_object, width);
	return *this;
}


size_t StructureBuilder::GetAlignment() const
{
	return BNGetStructureBuilderAlignment(m_object);
}


StructureBuilder& StructureBuilder::SetAlignment(size_t align)
{
	BNSetStructureBuilderAlignment(m_object, align);
	return *this;
}


bool StructureBuilder::IsPacked() const
{
	return BNIsStructureBuilderPacked(m_object);
}


StructureBuilder& StructureBuilder::SetPacked(bool packed)
{
	BNSetStructureBuilderPacked(m_object, packed);
	return *this;
}


bool StructureBuilder::IsUnion() const
{
	return BNIsStructureBuilderUnion(m_object);
}


StructureBuilder& StructureBuilder::SetStructureType(BNStructureType t)
{
	BNSetStructureBuilderType(m_object, t);
	return *this;
}


BNStructureType StructureBuilder::GetStructureType() const
{
	return BNGetStructureBuilderType(m_object);
}


StructureBuilder& StructureBuilder::AddMember(const Confidence<Ref<Type>>& type, const string& name)
{
	BNTypeWithConfidence tc;
	tc.type = type->GetObject();
	tc.confidence = type.GetConfidence();
	BNAddStructureBuilderMember(m_object, &tc, name.c_str());
	return *this;
}


StructureBuilder& StructureBuilder::AddMemberAtOffset(const Confidence<Ref<Type>>& type, const string& name, uint64_t offset)
{
	BNTypeWithConfidence tc;
	tc.type = type->GetObject();
	tc.confidence = type.GetConfidence();
	BNAddStructureBuilderMemberAtOffset(m_object, &tc, name.c_str(), offset);
	return *this;
}


StructureBuilder& StructureBuilder::RemoveMember(size_t idx)
{
	BNRemoveStructureBuilderMember(m_object, idx);
	return *this;
}


StructureBuilder& StructureBuilder::ReplaceMember(size_t idx, const Confidence<Ref<Type>>& type, const std::string& name)
{
	BNTypeWithConfidence tc;
	tc.type = type->GetObject();
	tc.confidence = type.GetConfidence();
	BNReplaceStructureBuilderMember(m_object, idx, &tc, name.c_str());
	return *this;
}


Enumeration::Enumeration(BNEnumeration* e)
{
	m_object = e;
}


vector<EnumerationMember> Enumeration::GetMembers() const
{
	size_t count;
	BNEnumerationMember* members = BNGetEnumerationMembers(m_object, &count);

	vector<EnumerationMember> result;
	result.reserve(count);
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


EnumerationBuilder::EnumerationBuilder()
{
	m_object = BNCreateEnumerationBuilder();
}


EnumerationBuilder::EnumerationBuilder(BNEnumerationBuilder* e)
{
	m_object = e;
}


EnumerationBuilder::EnumerationBuilder(const EnumerationBuilder& e)
{
	m_object = BNDuplicateEnumerationBuilder(e.m_object);
}


EnumerationBuilder::EnumerationBuilder(EnumerationBuilder&& e)
{
	m_object = e.m_object;
	e.m_object = BNCreateEnumerationBuilder();
}


EnumerationBuilder::EnumerationBuilder(Enumeration* e)
{
	m_object = BNCreateEnumerationBuilderFromEnumeration(e->GetObject());
}


EnumerationBuilder::~EnumerationBuilder()
{
	BNFreeEnumerationBuilder(m_object);
}


EnumerationBuilder& EnumerationBuilder::operator=(const EnumerationBuilder& e)
{
	if (this != &e)
	{
		BNFreeEnumerationBuilder(m_object);
		m_object = BNDuplicateEnumerationBuilder(e.m_object);
	}
	return *this;
}


EnumerationBuilder& EnumerationBuilder::operator=(EnumerationBuilder&& e)
{
	if (this != &e)
		std::swap(m_object, e.m_object);
	return *this;
}


EnumerationBuilder& EnumerationBuilder::operator=(Enumeration* e)
{
	BNFreeEnumerationBuilder(m_object);
	m_object = BNCreateEnumerationBuilderFromEnumeration(e->GetObject());
	return *this;
}


Ref<Enumeration> EnumerationBuilder::Finalize() const
{
	return new Enumeration(BNFinalizeEnumerationBuilder(m_object));
}


vector<EnumerationMember> EnumerationBuilder::GetMembers() const
{
	size_t count;
	BNEnumerationMember* members = BNGetEnumerationBuilderMembers(m_object, &count);

	vector<EnumerationMember> result;
	result.reserve(count);
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


EnumerationBuilder& EnumerationBuilder::AddMember(const string& name)
{
	BNAddEnumerationBuilderMember(m_object, name.c_str());
	return *this;
}


EnumerationBuilder& EnumerationBuilder::AddMemberWithValue(const string& name, uint64_t value)
{
	BNAddEnumerationBuilderMemberWithValue(m_object, name.c_str(), value);
	return *this;
}


EnumerationBuilder& EnumerationBuilder::RemoveMember(size_t idx)
{
	BNRemoveEnumerationBuilderMember(m_object, idx);
	return *this;
}


EnumerationBuilder& EnumerationBuilder::ReplaceMember(size_t idx, const string& name, uint64_t value)
{
	BNReplaceEnumerationBuilderMember(m_object, idx, name.c_str(), value);
	return *this;
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
