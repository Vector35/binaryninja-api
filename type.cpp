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
#include <cinttypes>

using namespace BinaryNinja;
using namespace std;


NameList::NameList(const string& join, size_t size) : m_join(join)
{
	m_name.reserve(size);
}


NameList::NameList(const BNQualifiedName* name)
{
	if (name->join)
		m_join = name->join;
	m_name.reserve(name->nameCount);
	for (size_t i = 0; i < name->nameCount; i++)
		m_name.push_back(name->name[i]);
}


NameList::NameList(const string& name, const string& join) : m_join(join)
{
	if (!name.empty())
		m_name.push_back(name);
}


NameList::NameList(const vector<string>& name, const string& join) : m_join(join), m_name(name) {}


NameList::NameList(const NameList& name, const string& join) : m_join(join), m_name(name.m_name) {}

NameList::NameList(const NameList& name) : m_join(name.m_join), m_name(name.m_name) {}

NameList::~NameList() {}

NameList& NameList::operator=(const string& name)
{
	m_name = vector<string> {name};
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
	m_join = name.m_join;
	return *this;
}


bool NameList::operator==(const NameList& other) const
{
	return m_name == other.m_name && m_join == other.m_join;
}


bool NameList::operator!=(const NameList& other) const
{
	return m_name != other.m_name || m_join != other.m_join;
}


bool NameList::operator<(const NameList& other) const
{
	if (m_name < other.m_name)
		return true;
	if (m_name > other.m_name)
		return false;
	return m_join < other.m_join;
}


bool NameList::operator>(const NameList& other) const
{
	if (m_name > other.m_name)
		return true;
	if (m_name < other.m_name)
		return false;
	return m_join > other.m_join;
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


string NameList::GetString(BNTokenEscapingType escaping) const
{
	bool first = true;
	string out;
	for (auto& name : m_name)
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
	return EscapeTypeName(out, escaping);
}


std::string NameList::EscapeTypeName(const std::string& name, BNTokenEscapingType escaping)
{
	char* str = BNEscapeTypeName(name.c_str(), escaping);
	std::string result(str);
	BNFreeString(str);
	return result;
}


std::string NameList::UnescapeTypeName(const std::string& name, BNTokenEscapingType escaping)
{
	char* str = BNUnescapeTypeName(name.c_str(), escaping);
	std::string result(str);
	BNFreeString(str);
	return result;
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


QualifiedName::QualifiedName() : NameList("::") {}


QualifiedName::QualifiedName(const BNQualifiedName* name) : NameList(name) {}


QualifiedName::QualifiedName(const string& name) : NameList(name, "::") {}


QualifiedName::QualifiedName(const vector<string>& name) : NameList(name, "::") {}


QualifiedName::QualifiedName(const QualifiedName& name) : NameList(name.m_name, "::") {}


QualifiedName::~QualifiedName() {}


QualifiedName& QualifiedName::operator=(const string& name)
{
	m_name = vector<string> {name};
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


QualifiedName QualifiedName::FromAPIObject(const BNQualifiedName* name)
{
	return QualifiedName(name);
}


NameSpace::NameSpace() : NameList("::") {}


NameSpace::NameSpace(const string& name) : NameList(name, "::") {}


NameSpace::NameSpace(const vector<string>& name) : NameList(name, "::") {}


NameSpace::NameSpace(const NameSpace& name) : NameList(name.m_name, "::") {}


NameSpace::~NameSpace() {}


NameSpace& NameSpace::operator=(const string& name)
{
	m_name = vector<string> {name};
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


TypeDefinitionLine TypeDefinitionLine::FromAPIObject(BNTypeDefinitionLine* line)
{
	TypeDefinitionLine result;
	result.lineType = line->lineType;
	result.tokens = InstructionTextToken::ConvertInstructionTextTokenList(line->tokens, line->count);
	result.type = new Type(BNNewTypeReference(line->type));
	result.rootType = new Type(BNNewTypeReference(line->rootType));
	result.rootTypeName = line->rootTypeName;
	result.baseType = line->baseType ? new NamedTypeReference(BNNewNamedTypeReference(line->baseType)) : nullptr;
	result.baseOffset = line->baseOffset;
	result.offset = line->offset;
	result.fieldIndex = line->fieldIndex;
	return result;
}


BNTypeDefinitionLine* TypeDefinitionLine::CreateTypeDefinitionLineList(
	const std::vector<TypeDefinitionLine>& lines)
{
	BNTypeDefinitionLine* result = new BNTypeDefinitionLine[lines.size()];
	for (size_t i = 0; i < lines.size(); ++i)
	{
		result[i].lineType = lines[i].lineType;
		result[i].tokens = InstructionTextToken::CreateInstructionTextTokenList(lines[i].tokens);
		result[i].count = lines[i].tokens.size();
		result[i].type = BNNewTypeReference(lines[i].type->GetObject());
		result[i].rootType = BNNewTypeReference(lines[i].rootType->GetObject());
		result[i].rootTypeName = BNAllocString(lines[i].rootTypeName.c_str());
		result[i].baseType = lines[i].baseType ? BNNewNamedTypeReference(lines[i].baseType->GetObject()) : nullptr;
		result[i].baseOffset = lines[i].baseOffset;
		result[i].offset = lines[i].offset;
		result[i].fieldIndex = lines[i].fieldIndex;
	}
	return result;
}


void TypeDefinitionLine::FreeTypeDefinitionLineList(BNTypeDefinitionLine* lines, size_t count)
{
	for (size_t i = 0; i < count; ++i)
	{
		InstructionTextToken::FreeInstructionTextTokenList(lines[i].tokens, lines[i].count);
		BNFreeType(lines[i].type);
		BNFreeType(lines[i].rootType);
		BNFreeNamedTypeReference(lines[i].baseType);
		BNFreeString(lines[i].rootTypeName);
	}
	delete[] lines;
}


BaseStructure::BaseStructure(NamedTypeReference* _type, uint64_t _offset, uint64_t _width) :
	type(_type), offset(_offset), width(_width)
{}


BaseStructure::BaseStructure(Type* _type, uint64_t _offset)
{
	type = _type->IsNamedTypeRefer() ? _type->GetNamedTypeReference() : _type->GetRegisteredName();
	offset = _offset;
	width = _type->GetWidth();
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


Confidence<bool> Type::IsVolatile() const
{
	BNBoolWithConfidence result = BNIsTypeVolatile(m_object);
	return Confidence<bool>(result.value, result.confidence);
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


string Type::GetString(Platform* platform, BNTokenEscapingType escaping) const
{
	char* str = BNGetTypeString(m_object, platform ? platform->GetObject() : nullptr, escaping);
	string result = str;
	BNFreeString(str);
	return result;
}


string Type::GetTypeAndName(const QualifiedName& nameList, BNTokenEscapingType escaping) const
{
	BNQualifiedName name = nameList.GetAPIObject();
	char* outName = BNGetTypeAndName(m_object, &name, escaping);
	QualifiedName::FreeAPIObject(&name);
	return outName;
}

string Type::GetStringBeforeName(Platform* platform, BNTokenEscapingType escaping) const
{
	char* str = BNGetTypeStringBeforeName(m_object, platform ? platform->GetObject() : nullptr, escaping);
	string result = str;
	BNFreeString(str);
	return result;
}


string Type::GetStringAfterName(Platform* platform, BNTokenEscapingType escaping) const
{
	char* str = BNGetTypeStringAfterName(m_object, platform ? platform->GetObject() : nullptr, escaping);
	string result = str;
	BNFreeString(str);
	return result;
}


vector<InstructionTextToken> Type::GetTokens(Platform* platform, uint8_t baseConfidence, BNTokenEscapingType escaping) const
{
	size_t count;
	BNInstructionTextToken* tokens =
	    BNGetTypeTokens(m_object, platform ? platform->GetObject() : nullptr, baseConfidence, escaping, &count);

	return InstructionTextToken::ConvertAndFreeInstructionTextTokenList(tokens, count);
}


vector<InstructionTextToken> Type::GetTokensBeforeName(Platform* platform, uint8_t baseConfidence, BNTokenEscapingType escaping) const
{
	size_t count;
	BNInstructionTextToken* tokens =
	    BNGetTypeTokensBeforeName(m_object, platform ? platform->GetObject() : nullptr, baseConfidence, escaping, &count);
	return InstructionTextToken::ConvertAndFreeInstructionTextTokenList(tokens, count);
}


vector<InstructionTextToken> Type::GetTokensAfterName(Platform* platform, uint8_t baseConfidence, BNTokenEscapingType escaping) const
{
	size_t count;
	BNInstructionTextToken* tokens =
	    BNGetTypeTokensAfterName(m_object, platform ? platform->GetObject() : nullptr, baseConfidence, escaping, &count);

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


Ref<Type> Type::WideCharType(size_t width, const string& altName)
{
	return new Type(BNCreateWideCharType(width, altName.c_str()));
}


Ref<Type> Type::StructureType(Structure* strct)
{
	return new Type(BNCreateStructureType(strct->GetObject()));
}


Ref<Type> Type::NamedType(
    NamedTypeReference* ref, size_t width, size_t align, const Confidence<bool>& cnst, const Confidence<bool>& vltl)
{
	BNBoolWithConfidence cnstConf;
	cnstConf.value = cnst.GetValue();
	cnstConf.confidence = cnst.GetConfidence();

	BNBoolWithConfidence vltlConf;
	vltlConf.value = vltl.GetValue();
	vltlConf.confidence = vltl.GetConfidence();

	return new Type(BNCreateNamedTypeReference(ref->GetObject(), width, align, &cnstConf, &vltlConf));
}


Ref<Type> Type::NamedType(const QualifiedName& name, Type* type)
{
	return NamedType("", name, type);
}


Ref<Type> Type::NamedType(const string& id, const QualifiedName& name, Type* type)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	BNType* coreObj = BNCreateNamedTypeReferenceFromTypeAndId(id.c_str(), &nameObj, type ? type->GetObject() : nullptr);
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


Ref<Type> Type::EnumerationType(Architecture* arch, Enumeration* enm, size_t width, const Confidence<bool>& isSigned)
{
	BNBoolWithConfidence isSignedConf;
	isSignedConf.value = isSigned.GetValue();
	isSignedConf.confidence = isSigned.GetConfidence();
	return new Type(
		BNCreateEnumerationType(arch ? arch->GetObject() : nullptr, enm->GetObject(), width, &isSignedConf));
}


Ref<Type> Type::EnumerationType(Enumeration* enm, size_t width, const Confidence<bool>& isSigned)
{
	BNBoolWithConfidence isSignedConf;
	isSignedConf.value = isSigned.GetValue();
	isSignedConf.confidence = isSigned.GetConfidence();
	return new Type(BNCreateEnumerationTypeOfWidth(enm->GetObject(), width, &isSignedConf));
}


Ref<Type> Type::PointerType(Architecture* arch, const Confidence<Ref<Type>>& type, const Confidence<bool>& cnst,
    const Confidence<bool>& vltl, BNReferenceType refType)
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


Ref<Type> Type::PointerType(size_t width, const Confidence<Ref<Type>>& type, const Confidence<bool>& cnst,
    const Confidence<bool>& vltl, BNReferenceType refType)
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
    const Confidence<Ref<CallingConvention>>& callingConvention, const std::vector<FunctionParameter>& params,
    const Confidence<bool>& varArg, const Confidence<int64_t>& stackAdjust)
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

	BNBoolWithConfidence canReturnConf;
	canReturnConf.value = true;
	canReturnConf.confidence = 0;

	BNOffsetWithConfidence stackAdjustConf;
	stackAdjustConf.value = stackAdjust.GetValue();
	stackAdjustConf.confidence = stackAdjust.GetConfidence();

	BNRegisterSetWithConfidence returnRegsConf;
	returnRegsConf.regs = nullptr;
	returnRegsConf.count = 0;
	returnRegsConf.confidence = 0;

	Type* type = new Type(BNCreateFunctionType(
	    &returnValueConf, &callingConventionConf, paramArray, params.size(), &varArgConf,
	    &canReturnConf, &stackAdjustConf, nullptr, nullptr, 0, &returnRegsConf, NoNameType));
	delete[] paramArray;
	return type;
}


Ref<Type> Type::FunctionType(const Confidence<Ref<Type>>& returnValue,
    const Confidence<Ref<CallingConvention>>& callingConvention,
    const std::vector<FunctionParameter>& params,
    const Confidence<bool>& hasVariableArguments,
    const Confidence<bool>& canReturn,
    const Confidence<int64_t>& stackAdjust,
    const std::map<uint32_t, Confidence<int32_t>>& regStackAdjust,
    const Confidence<std::vector<uint32_t>>& returnRegs,
    BNNameType ft)
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
	varArgConf.value = hasVariableArguments.GetValue();
	varArgConf.confidence = hasVariableArguments.GetConfidence();

	BNBoolWithConfidence canReturnConf;
	canReturnConf.value = canReturn.GetValue();
	canReturnConf.confidence = canReturn.GetConfidence();

	BNOffsetWithConfidence stackAdjustConf;
	stackAdjustConf.value = stackAdjust.GetValue();
	stackAdjustConf.confidence = stackAdjust.GetConfidence();

	std::vector<uint32_t> regStackAdjustRegs;
	std::vector<BNOffsetWithConfidence> regStackAdjustValues;
	size_t i = 0;
	for (const auto& adjust: regStackAdjust)
	{
		regStackAdjustRegs[i] = adjust.first;
		regStackAdjustValues[i].value = adjust.second.GetValue();
		regStackAdjustValues[i].confidence = adjust.second.GetConfidence();
		i ++;
	}

	std::vector<uint32_t> returnRegsRegs = returnRegs.GetValue();

	BNRegisterSetWithConfidence returnRegsConf;
	returnRegsConf.regs = returnRegsRegs.data();
	returnRegsConf.count = returnRegs->size();
	returnRegsConf.confidence = returnRegs.GetConfidence();

	Type* type = new Type(BNCreateFunctionType(
	    &returnValueConf, &callingConventionConf, paramArray, params.size(), &varArgConf,
	    &canReturnConf, &stackAdjustConf, regStackAdjustRegs.data(),
	    regStackAdjustValues.data(), regStackAdjust.size(), &returnRegsConf, NoNameType));
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

bool Type::IsReferenceOfType(BNNamedTypeReferenceClass refType)
{
	return (GetClass() == NamedTypeReferenceClass) && (GetNamedTypeReference()->GetTypeReferenceClass() == refType);
}

QualifiedName Type::GetStructureName() const
{
	BNQualifiedName name = BNTypeGetStructureName(m_object);
	QualifiedName result = QualifiedName::FromAPIObject(&name);
	BNFreeQualifiedName(&name);
	return result;
}


bool Type::IsSystemCall() const
{
	return BNTypeIsSystemCall(m_object);
}


uint32_t Type::GetSystemCallNumber() const
{
	return BNTypeGetSystemCallNumber(m_object);
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


bool Type::AddTypeMemberTokens(BinaryView* data, vector<InstructionTextToken>& tokens, int64_t offset,
    vector<string>& nameList, size_t size, bool indirect)
{
	size_t tokenCount;
	BNInstructionTextToken* list;

	size_t nameCount;
	char** names = nullptr;

	if (!BNAddTypeMemberTokens(
	        m_object, data->GetObject(), &list, &tokenCount, offset, &names, &nameCount, size, indirect))
		return false;

	vector<InstructionTextToken> newTokens =
	    InstructionTextToken::ConvertAndFreeInstructionTextTokenList(list, tokenCount);
	tokens.insert(tokens.end(), newTokens.begin(), newTokens.end());

	nameList.clear();
	nameList.reserve(nameCount);
	for (size_t i = 0; i < nameCount; i++)
		nameList.emplace_back(names[i]);

	BNFreeStringList(names, nameCount);

	return true;
}


std::vector<TypeDefinitionLine> Type::GetLines(Ref<BinaryView> data, const std::string& name,
	int lineWidth, bool collapsed, BNTokenEscapingType escaping)
{
	size_t count;
	BNTypeDefinitionLine* list =
		BNGetTypeLines(m_object, data->m_object, name.c_str(), lineWidth, collapsed, escaping, &count);

	std::vector<TypeDefinitionLine> results;
	for (size_t i = 0; i < count; i++)
	{
		TypeDefinitionLine line;
		line.lineType = list[i].lineType;
		line.tokens = InstructionTextToken::ConvertInstructionTextTokenList(list[i].tokens, list[i].count);
		line.type = new Type(BNNewTypeReference(list[i].type));
		line.rootType = list[i].rootType ? new Type(BNNewTypeReference(list[i].rootType)) : nullptr;
		line.rootTypeName = list[i].rootTypeName;
		line.baseType = list[i].baseType ? new NamedTypeReference(BNNewNamedTypeReference(list[i].baseType)) : nullptr;
		line.baseOffset = list[i].baseOffset;
		line.offset = list[i].offset;
		line.fieldIndex = list[i].fieldIndex;
		results.push_back(line);
	}

	BNFreeTypeDefinitionLineList(list, count);
	return results;
}


string Type::GetSizeSuffix(size_t size)
{
	char sizeStr[32];

	switch (size)
	{
	case 0:
		return "";
	case 1:
		return ".b";
	case 2:
		return ".w";
	case 4:
		return ".d";
	case 8:
		return ".q";
	case 10:
		return ".t";
	case 16:
		return ".o";
	default:
		snprintf(sizeStr, sizeof(sizeStr), ".%" PRIuPTR, size);
		return sizeStr;
	}
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


TypeBuilder& TypeBuilder::SetSigned(const Confidence<bool>& s)
{
	BNBoolWithConfidence bc;
	bc.value = s.GetValue();
	bc.confidence = s.GetConfidence();
	BNTypeBuilderSetSigned(m_object, &bc);
	return *this;
}


Confidence<Ref<Type>> TypeBuilder::GetChildType() const
{
	BNTypeWithConfidence type = BNGetTypeBuilderChildType(m_object);
	if (type.type)
		return Confidence<Ref<Type>>(new Type(type.type), type.confidence);
	return nullptr;
}


TypeBuilder& TypeBuilder::SetChildType(const Confidence<Ref<Type>>& child)
{
	BNTypeWithConfidence childType;
	childType.type = child->GetObject();
	childType.confidence = child.GetConfidence();
	BNTypeBuilderSetChildType(m_object, &childType);
	return *this;
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


TypeBuilder& TypeBuilder::SetNamedTypeReference(NamedTypeReference* ntr)
{
	BNSetTypeBuilderNamedTypeReference(m_object, ntr ? ntr->GetObject() : nullptr);
	return *this;
}


uint64_t TypeBuilder::GetElementCount() const
{
	return BNGetTypeBuilderElementCount(m_object);
}


uint64_t TypeBuilder::GetOffset() const
{
	return BNGetTypeBuilderOffset(m_object);
}


TypeBuilder& TypeBuilder::SetOffset(uint64_t offset)
{
	BNSetTypeBuilderOffset(m_object, offset);
	return *this;
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
	BNInstructionTextToken* tokens =
	    BNGetTypeBuilderTokens(m_object, platform ? platform->GetObject() : nullptr, baseConfidence, &count);

	return InstructionTextToken::ConvertAndFreeInstructionTextTokenList(tokens, count);
}


vector<InstructionTextToken> TypeBuilder::GetTokensBeforeName(Platform* platform, uint8_t baseConfidence) const
{
	size_t count;
	BNInstructionTextToken* tokens =
	    BNGetTypeBuilderTokensBeforeName(m_object, platform ? platform->GetObject() : nullptr, baseConfidence, &count);
	return InstructionTextToken::ConvertAndFreeInstructionTextTokenList(tokens, count);
}


vector<InstructionTextToken> TypeBuilder::GetTokensAfterName(Platform* platform, uint8_t baseConfidence) const
{
	size_t count;
	BNInstructionTextToken* tokens =
	    BNGetTypeBuilderTokensAfterName(m_object, platform ? platform->GetObject() : nullptr, baseConfidence, &count);

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


TypeBuilder TypeBuilder::WideCharType(size_t width, const string& altName)
{
	return TypeBuilder(BNCreateWideCharTypeBuilder(width, altName.c_str()));
}


TypeBuilder TypeBuilder::StructureType(Structure* strct)
{
	return TypeBuilder(BNCreateStructureTypeBuilder(strct->GetObject()));
}


TypeBuilder TypeBuilder::StructureType(StructureBuilder* strct)
{
	return TypeBuilder(BNCreateStructureTypeBuilderWithBuilder(strct->GetObject()));
}


TypeBuilder TypeBuilder::NamedType(
    NamedTypeReference* ref, size_t width, size_t align, const Confidence<bool>& cnst, const Confidence<bool>& vltl)
{
	BNBoolWithConfidence cnstConf;
	cnstConf.value = cnst.GetValue();
	cnstConf.confidence = cnst.GetConfidence();

	BNBoolWithConfidence vltlConf;
	vltlConf.value = vltl.GetValue();
	vltlConf.confidence = vltl.GetConfidence();
	return TypeBuilder(BNCreateNamedTypeReferenceBuilder(ref->GetObject(), width, align, &cnstConf, &vltlConf));
}


TypeBuilder TypeBuilder::NamedType(NamedTypeReferenceBuilder* ref, size_t width, size_t align,
    const Confidence<bool>& cnst, const Confidence<bool>& vltl)
{
	BNBoolWithConfidence cnstConf;
	cnstConf.value = cnst.GetValue();
	cnstConf.confidence = cnst.GetConfidence();

	BNBoolWithConfidence vltlConf;
	vltlConf.value = vltl.GetValue();
	vltlConf.confidence = vltl.GetConfidence();
	return TypeBuilder(
	    BNCreateNamedTypeReferenceBuilderWithBuilder(ref->GetObject(), width, align, &cnstConf, &vltlConf));
}


TypeBuilder TypeBuilder::NamedType(const QualifiedName& name, Type* type)
{
	return NamedType("", name, type);
}


TypeBuilder TypeBuilder::NamedType(const string& id, const QualifiedName& name, Type* type)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	BNTypeBuilder* coreObj =
	    BNCreateNamedTypeReferenceBuilderFromTypeAndId(id.c_str(), &nameObj, type ? type->GetObject() : nullptr);
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


TypeBuilder TypeBuilder::EnumerationType(
    Architecture* arch, Enumeration* enm, size_t width, const Confidence<bool>& isSigned)
{
	BNBoolWithConfidence isSignedConf;
	isSignedConf.value = isSigned.GetValue();
	isSignedConf.confidence = isSigned.GetConfidence();
	return TypeBuilder(
	    BNCreateEnumerationTypeBuilder(arch ? arch->GetObject() : nullptr, enm->GetObject(), width, &isSignedConf));
}


TypeBuilder TypeBuilder::EnumerationType(
    Architecture* arch, EnumerationBuilder* enm, size_t width, const Confidence<bool>& isSigned)
{
	BNBoolWithConfidence isSignedConf;
	isSignedConf.value = isSigned.GetValue();
	isSignedConf.confidence = isSigned.GetConfidence();
	return TypeBuilder(BNCreateEnumerationTypeBuilderWithBuilder(
		arch ? arch->GetObject() : nullptr, enm->GetObject(), width, &isSignedConf));
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


TypeBuilder TypeBuilder::PointerType(size_t width, const Confidence<Ref<Type>>& type, const Confidence<bool>& cnst,
    const Confidence<bool>& vltl, BNReferenceType refType)
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


static BNFunctionParameter* GetParamArray(const std::vector<FunctionParameter>& params, size_t& count)
{
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
	count = params.size();
	return paramArray;
}

TypeBuilder TypeBuilder::FunctionType(const Confidence<Ref<Type>>& returnValue,
    const Confidence<Ref<CallingConvention>>& callingConvention, const std::vector<FunctionParameter>& params,
    const Confidence<bool>& varArg, const Confidence<int64_t>& stackAdjust)
{
	BNTypeWithConfidence returnValueConf;
	returnValueConf.type = returnValue->GetObject();
	returnValueConf.confidence = returnValue.GetConfidence();

	BNCallingConventionWithConfidence callingConventionConf;
	callingConventionConf.convention = callingConvention ? callingConvention->GetObject() : nullptr;
	callingConventionConf.confidence = callingConvention.GetConfidence();

	size_t paramCount = 0;
	BNFunctionParameter* paramArray = GetParamArray(params, paramCount);

	BNBoolWithConfidence varArgConf;
	varArgConf.value = varArg.GetValue();
	varArgConf.confidence = varArg.GetConfidence();

	BNOffsetWithConfidence stackAdjustConf;
	stackAdjustConf.value = stackAdjust.GetValue();
	stackAdjustConf.confidence = stackAdjust.GetConfidence();

	BNBoolWithConfidence canReturnConf;
	canReturnConf.value = true;
	canReturnConf.confidence = 0;

	BNRegisterSetWithConfidence returnRegsConf;
	returnRegsConf.regs = nullptr;
	returnRegsConf.count = 0;
	returnRegsConf.confidence = 0;

	TypeBuilder type(BNCreateFunctionTypeBuilder(
		&returnValueConf, &callingConventionConf, paramArray, paramCount, &varArgConf,
		&canReturnConf, &stackAdjustConf, nullptr, nullptr, 0, &returnRegsConf, NoNameType));
	delete[] paramArray;
	return type;
}


TypeBuilder TypeBuilder::FunctionType(const Confidence<Ref<Type>>& returnValue,
	const Confidence<Ref<CallingConvention>>& callingConvention,
	const std::vector<FunctionParameter>& params,
	const Confidence<bool>& hasVariableArguments,
	const Confidence<bool>& canReturn,
	const Confidence<int64_t>& stackAdjust,
	const std::map<uint32_t, Confidence<int32_t>>& regStackAdjust,
	const Confidence<std::vector<uint32_t>>& returnRegs,
	BNNameType ft)
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
	varArgConf.value = hasVariableArguments.GetValue();
	varArgConf.confidence = hasVariableArguments.GetConfidence();

	BNBoolWithConfidence canReturnConf;
	canReturnConf.value = canReturn.GetValue();
	canReturnConf.confidence = canReturn.GetConfidence();

	BNOffsetWithConfidence stackAdjustConf;
	stackAdjustConf.value = stackAdjust.GetValue();
	stackAdjustConf.confidence = stackAdjust.GetConfidence();

	std::vector<uint32_t> regStackAdjustRegs;
	std::vector<BNOffsetWithConfidence> regStackAdjustValues;
	size_t i = 0;
	for (const auto& adjust: regStackAdjust)
	{
		regStackAdjustRegs[i] = adjust.first;
		regStackAdjustValues[i].value = adjust.second.GetValue();
		regStackAdjustValues[i].confidence = adjust.second.GetConfidence();
		i ++;
	}

	std::vector<uint32_t> returnRegsRegs = returnRegs.GetValue();

	BNRegisterSetWithConfidence returnRegsConf;
	returnRegsConf.regs = returnRegsRegs.data();
	returnRegsConf.count = returnRegs->size();
	returnRegsConf.confidence = returnRegs.GetConfidence();

	TypeBuilder type(BNCreateFunctionTypeBuilder(
		&returnValueConf, &callingConventionConf, paramArray, params.size(), &varArgConf,
		&canReturnConf, &stackAdjustConf, regStackAdjustRegs.data(),
		regStackAdjustValues.data(), regStackAdjust.size(), &returnRegsConf, NoNameType));
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


TypeBuilder& TypeBuilder::SetParameters(const std::vector<FunctionParameter>& params)
{
	size_t paramCount = 0;
	BNFunctionParameter* paramArray = GetParamArray(params, paramCount);
	BNSetFunctionTypeBuilderParameters(m_object, paramArray, paramCount);
	return *this;
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


TypeBuilder& TypeBuilder::SetAlternateName(const string& name)
{
	BNTypeBuilderSetAlternateName(m_object, name.c_str());
	return *this;
}


TypeBuilder& TypeBuilder::SetSystemCall(bool sc, uint32_t n)
{
	BNTypeBuilderSetSystemCallNumber(m_object, sc, n);
	return *this;
}


bool TypeBuilder::IsSystemCall() const
{
	return BNTypeBuilderIsSystemCall(m_object);
}


uint32_t TypeBuilder::GetSystemCallNumber() const
{
	return BNTypeBuilderGetSystemCallNumber(m_object);
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


BNNamedTypeReferenceClass NamedTypeReference::GetTypeReferenceClass() const
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


Ref<NamedTypeReference> NamedTypeReference::GenerateAutoTypeReference(
    BNNamedTypeReferenceClass cls, const string& source, const QualifiedName& name)
{
	string id = Type::GenerateAutoTypeId(source, name);
	return new NamedTypeReference(cls, id, name);
}


Ref<NamedTypeReference> NamedTypeReference::GenerateAutoDemangledTypeReference(
    BNNamedTypeReferenceClass cls, const QualifiedName& name)
{
	string id = Type::GenerateAutoDemangledTypeId(name);
	return new NamedTypeReference(cls, id, name);
}


Ref<NamedTypeReference> NamedTypeReference::GenerateAutoDebugTypeReference(
    BNNamedTypeReferenceClass cls, const QualifiedName& name)
{
	string id = Type::GenerateAutoDebugTypeId(name);
	return new NamedTypeReference(cls, id, name);
}


NamedTypeReferenceBuilder::NamedTypeReferenceBuilder(BNNamedTypeReferenceBuilder* nt)
{
	m_object = nt;
}


NamedTypeReferenceBuilder::NamedTypeReferenceBuilder(
    BNNamedTypeReferenceClass cls, const std::string& id, const QualifiedName& name)
{
	BNQualifiedName n = name.GetAPIObject();
	m_object = BNCreateNamedTypeBuilder(cls, id.c_str(), &n);
	QualifiedName::FreeAPIObject(&n);
}

NamedTypeReferenceBuilder::~NamedTypeReferenceBuilder()
{
	BNFreeNamedTypeReferenceBuilder(m_object);
}


BNNamedTypeReferenceClass NamedTypeReferenceBuilder::GetTypeReferenceClass() const
{
	return BNGetTypeReferenceBuilderClass(m_object);
}


std::string NamedTypeReferenceBuilder::GetTypeId() const
{
	char* str = BNGetTypeReferenceBuilderId(m_object);
	string result = str;
	BNFreeString(str);
	return result;
}


QualifiedName NamedTypeReferenceBuilder::GetName() const
{
	BNQualifiedName name = BNGetTypeReferenceBuilderName(m_object);
	QualifiedName result = QualifiedName::FromAPIObject(&name);
	BNFreeQualifiedName(&name);
	return result;
}


void NamedTypeReferenceBuilder::SetTypeReferenceClass(BNNamedTypeReferenceClass type)
{
	BNSetNamedTypeReferenceBuilderTypeClass(m_object, type);
}


void NamedTypeReferenceBuilder::SetTypeId(const string& id)
{
	BNSetNamedTypeReferenceBuilderTypeId(m_object, id.c_str());
}


void NamedTypeReferenceBuilder::SetName(const QualifiedName& name)
{
	BNQualifiedName n = name.GetAPIObject();
	BNSetNamedTypeReferenceBuilderName(m_object, &n);
	QualifiedName::FreeAPIObject(&n);
}


Ref<NamedTypeReference> NamedTypeReferenceBuilder::Finalize()
{
	BNNamedTypeReference* ref = BNFinalizeNamedTypeReferenceBuilder(m_object);
	if (ref)
		return new NamedTypeReference(ref);
	return nullptr;
}


Structure::Structure(BNStructure* s)
{
	m_object = s;
}


vector<BaseStructure> Structure::GetBaseStructures() const
{
	size_t count;
	BNBaseStructure* bases = BNGetBaseStructuresForStructure(m_object, &count);

	vector<BaseStructure> result;
	for (size_t i = 0; i < count; i++)
	{
		BaseStructure base(
			new NamedTypeReference(BNNewNamedTypeReference(bases[i].type)), bases[i].offset, bases[i].width);
		result.push_back(base);
	}

	BNFreeBaseStructureList(bases, count);
	return result;
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


vector<InheritedStructureMember> Structure::GetMembersIncludingInherited(BinaryView* view) const
{
	size_t count;
	BNInheritedStructureMember* members = BNGetStructureMembersIncludingInherited(m_object, view->GetObject(), &count);

	vector<InheritedStructureMember> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		InheritedStructureMember member;
		member.base = members[i].base ? new NamedTypeReference(BNNewNamedTypeReference(members[i].base)) : nullptr;
		member.baseOffset = members[i].baseOffset;
		member.member.type = new Type(BNNewTypeReference(members[i].member.type));
		member.member.name = members[i].member.name;
		member.member.offset = members[i].member.offset;
		member.memberIndex = members[i].memberIndex;
		result.push_back(member);
	}

	BNFreeInheritedStructureMemberList(members, count);
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


int64_t Structure::GetPointerOffset() const
{
	return BNGetStructurePointerOffset(m_object);
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


bool Structure::PropagateDataVariableReferences() const
{
	return BNStructurePropagatesDataVariableReferences(m_object);
}


BNStructureVariant Structure::GetStructureType() const
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


StructureBuilder::StructureBuilder(BNStructureVariant type, bool packed)
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


vector<BaseStructure> StructureBuilder::GetBaseStructures() const
{
	size_t count;
	BNBaseStructure* bases = BNGetBaseStructuresForStructureBuilder(m_object, &count);

	vector<BaseStructure> result;
	for (size_t i = 0; i < count; i++)
	{
		BaseStructure base(
			new NamedTypeReference(BNNewNamedTypeReference(bases[i].type)), bases[i].offset, bases[i].width);
		result.push_back(base);
	}

	BNFreeBaseStructureList(bases, count);
	return result;
}


StructureBuilder& StructureBuilder::SetBaseStructures(const vector<BaseStructure>& bases)
{
	BNBaseStructure* baseObjs = new BNBaseStructure[bases.size()];
	for (size_t i = 0; i < bases.size(); i++)
	{
		baseObjs[i].type = bases[i].type->GetObject();
		baseObjs[i].offset = bases[i].offset;
		baseObjs[i].width = bases[i].width;
	}

	BNSetBaseStructuresForStructureBuilder(m_object, baseObjs, bases.size());
	delete[] baseObjs;
	return *this;
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


int64_t StructureBuilder::GetPointerOffset() const
{
	return BNGetStructureBuilderPointerOffset(m_object);
}


StructureBuilder& StructureBuilder::SetPointerOffset(int64_t offset)
{
	BNSetStructureBuilderPointerOffset(m_object, offset);
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


bool StructureBuilder::PropagateDataVariableReferences() const
{
	return BNStructureBuilderPropagatesDataVariableReferences(m_object);
}


StructureBuilder& StructureBuilder::SetPropagateDataVariableReferences(bool value)
{
	BNSetStructureBuilderPropagatesDataVariableReferences(m_object, value);
	return *this;
}


StructureBuilder& StructureBuilder::SetStructureType(BNStructureVariant t)
{
	BNSetStructureBuilderType(m_object, t);
	return *this;
}


BNStructureVariant StructureBuilder::GetStructureType() const
{
	return BNGetStructureBuilderType(m_object);
}


StructureBuilder& StructureBuilder::AddMember(
    const Confidence<Ref<Type>>& type, const string& name, BNMemberAccess access, BNMemberScope scope)
{
	BNTypeWithConfidence tc;
	tc.type = type->GetObject();
	tc.confidence = type.GetConfidence();
	BNAddStructureBuilderMember(m_object, &tc, name.c_str(), access, scope);
	return *this;
}


StructureBuilder& StructureBuilder::AddMemberAtOffset(const Confidence<Ref<Type>>& type, const string& name,
    uint64_t offset, bool overwriteExisting, BNMemberAccess access, BNMemberScope scope)
{
	BNTypeWithConfidence tc;
	tc.type = type->GetObject();
	tc.confidence = type.GetConfidence();
	BNAddStructureBuilderMemberAtOffset(m_object, &tc, name.c_str(), offset, overwriteExisting, access, scope);
	return *this;
}


StructureBuilder& StructureBuilder::RemoveMember(size_t idx)
{
	BNRemoveStructureBuilderMember(m_object, idx);
	return *this;
}


StructureBuilder& StructureBuilder::ReplaceMember(
    size_t idx, const Confidence<Ref<Type>>& type, const std::string& name, bool overwriteExisting)
{
	BNTypeWithConfidence tc;
	tc.type = type->GetObject();
	tc.confidence = type.GetConfidence();
	BNReplaceStructureBuilderMember(m_object, idx, &tc, name.c_str(), overwriteExisting);
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


vector<InstructionTextToken> Enumeration::GetTokensForValue(uint64_t value, size_t width, Ref<Type> type)
{
	size_t count;
	BNInstructionTextToken* tokens = BNGetEnumerationTokensForValue(m_object, value, width, &count, type->GetObject());

	return InstructionTextToken::ConvertAndFreeInstructionTextTokenList(tokens, count);
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


bool BinaryNinja::PreprocessSource(
    const string& source, const string& fileName, string& output, string& errors, const vector<string>& includeDirs)
{
	char* outStr;
	char* errorStr;
	const char** includeDirList = new const char*[includeDirs.size()];

	for (size_t i = 0; i < includeDirs.size(); i++)
		includeDirList[i] = includeDirs[i].c_str();

	bool result =
	    BNPreprocessSource(source.c_str(), fileName.c_str(), &outStr, &errorStr, includeDirList, includeDirs.size());

	output = outStr;
	errors = errorStr;

	BNFreeString(outStr);
	BNFreeString(errorStr);
	delete[] includeDirList;
	return result;
}
