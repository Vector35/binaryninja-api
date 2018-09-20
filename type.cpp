// Copyright (c) 2015-2017 Vector 35 LLC
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
	m_name.push_back(name);
}


NameList::NameList(const vector<string>& name, const string& join): m_join(join), m_name(name)
{
}


NameList::NameList(const NameList& name, const string& join): m_join(join), m_name(name.m_name)
{
}


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
			out = m_join + name;
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
	for (size_t i = 0; i < name->nameCount; i++)
		BNFreeString(name->name[i]);
	BNFreeString(name->join);
	delete[] name->name;
}


NameSpace NameSpace::FromAPIObject(const BNNameSpace* name)
{
	NameSpace result;
	for (size_t i = 0; i < name->nameCount; i++)
		result.push_back(name->name[i]);
	return result;
}


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


bool Type::IsFloat() const
{
	return BNIsTypeFloatingPoint(m_object);
}


Confidence<BNMemberScope> Type::GetScope() const
{
	BNMemberScopeWithConfidence result = BNTypeGetMemberScope(m_object);
	return Confidence<BNMemberScope>(result.value, result.confidence);
}


void Type::SetScope(const Confidence<BNMemberScope>& scope)
{
	BNMemberScopeWithConfidence mc;
	mc.value = scope.GetValue();
	mc.confidence = scope.GetConfidence();
	return BNTypeSetMemberScope(m_object, &mc);
}


Confidence<BNMemberAccess> Type::GetAccess() const
{
	BNMemberAccessWithConfidence result = BNTypeGetMemberAccess(m_object);
	return Confidence<BNMemberAccess>(result.value, result.confidence);
}


void Type::SetAccess(const Confidence<BNMemberAccess>& access)
{
	BNMemberAccessWithConfidence mc;
	mc.value = access.GetValue();
	mc.confidence = access.GetConfidence();
	return BNTypeSetMemberAccess(m_object, &mc);
}


void Type::SetConst(const Confidence<bool>& cnst)
{
	BNBoolWithConfidence bc;
	bc.value = cnst.GetValue();
	bc.confidence = cnst.GetConfidence();
	BNTypeSetConst(m_object, &bc);
}


void Type::SetVolatile(const Confidence<bool>& vltl)
{
	BNBoolWithConfidence bc;
	bc.value = vltl.GetValue();
	bc.confidence = vltl.GetConfidence();
	BNTypeSetVolatile(m_object, &bc);
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

	vector<InstructionTextToken> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.emplace_back(tokens[i].type, tokens[i].context, tokens[i].text, tokens[i].address, tokens[i].value, tokens[i].size,
			tokens[i].operand, tokens[i].confidence);

	BNFreeTokenList(tokens, count);
	return result;
}


vector<InstructionTextToken> Type::GetTokensBeforeName(Platform* platform, uint8_t baseConfidence) const
{
	size_t count;
	BNInstructionTextToken* tokens = BNGetTypeTokensBeforeName(m_object,
		platform ? platform->GetObject() : nullptr, baseConfidence, &count);

	vector<InstructionTextToken> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.emplace_back(tokens[i].type, tokens[i].context, tokens[i].text, tokens[i].address, tokens[i].value, tokens[i].size,
			tokens[i].operand, tokens[i].confidence);

	BNFreeTokenList(tokens, count);
	return result;
}


vector<InstructionTextToken> Type::GetTokensAfterName(Platform* platform, uint8_t baseConfidence) const
{
	size_t count;
	BNInstructionTextToken* tokens = BNGetTypeTokensAfterName(m_object,
		platform ? platform->GetObject() : nullptr, baseConfidence, &count);

	vector<InstructionTextToken> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.emplace_back(tokens[i].type, tokens[i].context, tokens[i].text, tokens[i].address, tokens[i].value, tokens[i].size,
			tokens[i].operand, tokens[i].confidence);

	BNFreeTokenList(tokens, count);
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


void Type::SetFunctionCanReturn(const Confidence<bool>& canReturn)
{
	BNBoolWithConfidence bc;
	bc.value = canReturn.GetValue();
	bc.confidence = canReturn.GetConfidence();
	BNSetFunctionTypeCanReturn(m_object, &bc);
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


QualifiedName Type::GetTypeName() const
{
	BNQualifiedName name = BNTypeGetTypeName(m_object);
	QualifiedName result = QualifiedName::FromAPIObject(&name);
	BNFreeQualifiedName(&name);
	return result;
}


void Type::SetTypeName(const QualifiedName& names)
{
	BNQualifiedName nameObj = names.GetAPIObject();
	BNTypeSetTypeName(m_object, &nameObj);
	QualifiedName::FreeAPIObject(&nameObj);
}


Confidence<Ref<Type>> Type::WithConfidence(uint8_t conf)
{
	return Confidence<Ref<Type>>(this, conf);
}


NamedTypeReference::NamedTypeReference(BNNamedTypeReference* nt)
{
	m_object = nt;
}


NamedTypeReference::NamedTypeReference(BNNamedTypeReferenceClass cls, const string& id, const QualifiedName& names)
{
	m_object = BNCreateNamedType();
	BNSetTypeReferenceClass(m_object, cls);
	if (id.size() != 0)
	{
		BNSetTypeReferenceId(m_object, id.c_str());
	}
	if (names.size() != 0)
	{
		BNQualifiedName nameObj = names.GetAPIObject();
		BNSetTypeReferenceName(m_object, &nameObj);
		QualifiedName::FreeAPIObject(&nameObj);
	}
}


void NamedTypeReference::SetTypeClass(BNNamedTypeReferenceClass cls)
{
	BNSetTypeReferenceClass(m_object, cls);
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


void NamedTypeReference::SetTypeId(const string& id)
{
	BNSetTypeReferenceId(m_object, id.c_str());
}


void NamedTypeReference::SetName(const QualifiedName& names)
{
	BNQualifiedName nameObj = names.GetAPIObject();
	BNSetTypeReferenceName(m_object, &nameObj);
	QualifiedName::FreeAPIObject(&nameObj);
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


Structure::Structure()
{
	m_object = BNCreateStructure();
}


Structure::Structure(BNStructureType type, bool packed)
{
	m_object = BNCreateStructureWithOptions(type, packed);
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


void Structure::SetStructureType(BNStructureType t)
{
	BNSetStructureType(m_object, t);
}


BNStructureType Structure::GetStructureType() const
{
	return BNGetStructureType(m_object);
}


void Structure::AddMember(const Confidence<Ref<Type>>& type, const string& name)
{
	BNTypeWithConfidence tc;
	tc.type = type->GetObject();
	tc.confidence = type.GetConfidence();
	BNAddStructureMember(m_object, &tc, name.c_str());
}


void Structure::AddMemberAtOffset(const Confidence<Ref<Type>>& type, const string& name, uint64_t offset)
{
	BNTypeWithConfidence tc;
	tc.type = type->GetObject();
	tc.confidence = type.GetConfidence();
	BNAddStructureMemberAtOffset(m_object, &tc, name.c_str(), offset);
}


void Structure::RemoveMember(size_t idx)
{
	BNRemoveStructureMember(m_object, idx);
}


void Structure::ReplaceMember(size_t idx, const Confidence<Ref<Type>>& type, const std::string& name)
{
	BNTypeWithConfidence tc;
	tc.type = type->GetObject();
	tc.confidence = type.GetConfidence();
	BNReplaceStructureMember(m_object, idx, &tc, name.c_str());
}


Enumeration::Enumeration(BNEnumeration* e)
{
	m_object = e;
}


Enumeration::Enumeration()
{
	m_object = BNCreateEnumeration();
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
