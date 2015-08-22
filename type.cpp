#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


Type::Type(BNType* type): m_type(type)
{
}


Type::~Type()
{
	BNFreeType(m_type);
}


BNTypeClass Type::GetClass() const
{
	return BNGetTypeClass(m_type);
}


uint64_t Type::GetWidth() const
{
	return BNGetTypeWidth(m_type);
}


size_t Type::GetAlignment() const
{
	return BNGetTypeAlignment(m_type);
}


bool Type::IsSigned() const
{
	return BNIsTypeSigned(m_type);
}


bool Type::IsConst() const
{
	return BNIsTypeConst(m_type);
}


bool Type::IsFloat() const
{
	return BNIsTypeFloatingPoint(m_type);
}


Ref<Type> Type::GetChildType() const
{
	BNType* type = BNGetChildType(m_type);
	if (type)
		return new Type(type);
	return nullptr;
}


vector<NameAndType> Type::GetParameters() const
{
	size_t count;
	BNNameAndType* types = BNGetTypeParameters(m_type, &count);

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
	return BNTypeHasVariableArguments(m_type);
}


bool Type::CanReturn() const
{
	return BNFunctionTypeCanReturn(m_type);
}


Ref<Structure> Type::GetStructure() const
{
	BNStructure* s = BNGetTypeStructure(m_type);
	if (s)
		return new Structure(s);
	return nullptr;
}


Ref<Enumeration> Type::GetEnumeration() const
{
	BNEnumeration* e = BNGetTypeEnumeration(m_type);
	if (e)
		return new Enumeration(e);
	return nullptr;
}


uint64_t Type::GetElementCount() const
{
	return BNGetTypeElementCount(m_type);
}


string Type::GetString() const
{
	char* str = BNGetTypeString(m_type);
	string result = str;
	BNFreeString(str);
	return result;
}


string Type::GetStringBeforeName() const
{
	char* str = BNGetTypeStringBeforeName(m_type);
	string result = str;
	BNFreeString(str);
	return result;
}


string Type::GetStringAfterName() const
{
	char* str = BNGetTypeStringAfterName(m_type);
	string result = str;
	BNFreeString(str);
	return result;
}


Ref<Type> Type::VoidType()
{
	return new Type(BNCreateVoidType());
}


Ref<Type> Type::BoolType()
{
	return new Type(BNCreateBoolType());
}


Ref<Type> Type::IntegerType(size_t width, bool sign)
{
	return new Type(BNCreateIntegerType(width, sign));
}


Ref<Type> Type::FloatType(size_t width)
{
	return new Type(BNCreateFloatType(width));
}


Ref<Type> Type::StructureType(Structure* strct)
{
	return new Type(BNCreateStructureType(strct->GetStructureObject()));
}


Ref<Type> Type::EnumerationType(Architecture* arch, Enumeration* enm, size_t width)
{
	return new Type(BNCreateEnumerationType(arch->GetArchitectureObject(), enm->GetEnumerationObject(), width));
}


Ref<Type> Type::PointerType(Architecture* arch, Type* type, bool cnst)
{
	return new Type(BNCreatePointerType(arch->GetArchitectureObject(), type->GetTypeObject(), cnst));
}


Ref<Type> Type::ArrayType(Type* type, uint64_t elem)
{
	return new Type(BNCreateArrayType(type->GetTypeObject(), elem));
}


Ref<Type> Type::FunctionType(Type* returnValue, BNCallingConvention callingConvention,
                             const std::vector<NameAndType>& params, bool varArg)
{
	BNNameAndType* paramArray = new BNNameAndType[params.size()];
	for (size_t i = 0; i < params.size(); i++)
	{
		paramArray[i].name = (char*)params[i].name.c_str();
		paramArray[i].type = params[i].type->GetTypeObject();
	}

	Type* type = new Type(BNCreateFunctionType(returnValue->GetTypeObject(), callingConvention,
	                      paramArray, params.size(), varArg));
	delete[] paramArray;
	return type;
}


Structure::Structure(BNStructure* s): m_struct(s)
{
}


Structure::~Structure()
{
	BNFreeStructure(m_struct);
}


string Structure::GetName() const
{
	char* name = BNGetStructureName(m_struct);
	string result = name;
	BNFreeString(name);
	return result;
}


void Structure::SetName(const string& name)
{
	BNSetStructureName(m_struct, name.c_str());
}


vector<StructureMember> Structure::GetMembers() const
{
	size_t count;
	BNStructureMember* members = BNGetStructureMembers(m_struct, &count);

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
	return BNGetStructureWidth(m_struct);
}


size_t Structure::GetAlignment() const
{
	return BNGetStructureAlignment(m_struct);
}


bool Structure::IsPacked() const
{
	return BNIsStructurePacked(m_struct);
}


void Structure::SetPacked(bool packed)
{
	BNSetStructurePacked(m_struct, packed);
}


bool Structure::IsUnion() const
{
	return BNIsStructureUnion(m_struct);
}


void Structure::SetUnion(bool u)
{
	BNSetStructureUnion(m_struct, u);
}


void Structure::AddMember(Type* type, const string& name)
{
	BNAddStructureMember(m_struct, type->GetTypeObject(), name.c_str());
}


void Structure::AddMemberAtOffset(Type* type, const string& name, uint64_t offset)
{
	BNAddStructureMemberAtOffset(m_struct, type->GetTypeObject(), name.c_str(), offset);
}


void Structure::RemoveMember(size_t idx)
{
	BNRemoveStructureMember(m_struct, idx);
}


Enumeration::Enumeration(BNEnumeration* e): m_enum(e)
{
}


Enumeration::~Enumeration()
{
	BNFreeEnumeration(m_enum);
}


string Enumeration::GetName() const
{
	char* name = BNGetEnumerationName(m_enum);
	string result = name;
	BNFreeString(name);
	return result;
}


void Enumeration::SetName(const string& name)
{
	BNSetEnumerationName(m_enum, name.c_str());
}


vector<EnumerationMember> Enumeration::GetMembers() const
{
	size_t count;
	BNEnumerationMember* members = BNGetEnumerationMembers(m_enum, &count);

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
	BNAddEnumerationMember(m_enum, name.c_str());
}


void Enumeration::AddMemberWithValue(const string& name, uint64_t value)
{
	BNAddEnumerationMemberWithValue(m_enum, name.c_str(), value);
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


bool BinaryNinja::ParseTypesFromSource(Architecture* arch, const string& source, const string& fileName,
                                       map<string, Ref<Type>>& types, map<string, Ref<Type>>& variables,
                                       map<string, Ref<Type>>& functions, string& errors,
                                       const vector<string>& includeDirs)
{
	BNTypeParserResult result;
	char* errorStr;
	const char** includeDirList = new const char*[includeDirs.size()];

	for (size_t i = 0; i < includeDirs.size(); i++)
		includeDirList[i] = includeDirs[i].c_str();

	types.clear();
	variables.clear();
	functions.clear();

	bool ok = BNParseTypesFromSource(arch->GetArchitectureObject(), source.c_str(), fileName.c_str(), &result,
	                                 &errorStr, includeDirList, includeDirs.size());
	errors = errorStr;
	BNFreeString(errorStr);
	if (!ok)
		return false;

	for (size_t i = 0; i < result.typeCount; i++)
		types[result.types[i].name] = new Type(BNNewTypeReference(result.types[i].type));
	for (size_t i = 0; i < result.variableCount; i++)
		types[result.variables[i].name] = new Type(BNNewTypeReference(result.variables[i].type));
	for (size_t i = 0; i < result.functionCount; i++)
		types[result.functions[i].name] = new Type(BNNewTypeReference(result.functions[i].type));
	BNFreeTypeParserResult(&result);
	return true;
}


bool BinaryNinja::ParseTypesFromSourceFile(Architecture* arch, const string& fileName,
                                           map<string, Ref<Type>>& types, map<string, Ref<Type>>& variables,
                                           map<string, Ref<Type>>& functions, string& errors,
                                           const vector<string>& includeDirs)
{
	BNTypeParserResult result;
	char* errorStr;
	const char** includeDirList = new const char*[includeDirs.size()];

	for (size_t i = 0; i < includeDirs.size(); i++)
		includeDirList[i] = includeDirs[i].c_str();

	types.clear();
	variables.clear();
	functions.clear();

	bool ok = BNParseTypesFromSourceFile(arch->GetArchitectureObject(), fileName.c_str(), &result,
	                                     &errorStr, includeDirList, includeDirs.size());
	errors = errorStr;
	BNFreeString(errorStr);
	if (!ok)
		return false;

	for (size_t i = 0; i < result.typeCount; i++)
		types[result.types[i].name] = new Type(BNNewTypeReference(result.types[i].type));
	for (size_t i = 0; i < result.variableCount; i++)
		variables[result.variables[i].name] = new Type(BNNewTypeReference(result.variables[i].type));
	for (size_t i = 0; i < result.functionCount; i++)
		functions[result.functions[i].name] = new Type(BNNewTypeReference(result.functions[i].type));
	BNFreeTypeParserResult(&result);
	return true;
}
