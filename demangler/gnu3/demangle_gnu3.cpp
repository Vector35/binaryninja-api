// Copyright 2016-2026 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Includes snippets from LLVM, which is under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.

#include "demangle_gnu3.h"
#include <stdarg.h>
#include <algorithm>
#include <memory>


#ifdef BINARYNINJACORE_LIBRARY
using namespace BinaryNinjaCore;
#else
using namespace BinaryNinja;
using namespace std;
#endif


static constexpr size_t MAX_DEMANGLE_NESTING_DEPTH = 1024;

static BNTypeClass GetFinalizedTypeClass(const Ref<Type>& type)
{
#ifdef BINARYNINJACORE_LIBRARY
	return type->GetTypeClass();
#else
	return type->GetClass();
#endif
}

#define hash(x,y) (64 * x + y)

#undef GNUDEMANGLE_DEBUG
#ifdef GNUDEMANGLE_DEBUG  // This makes it not thread safe!
static string _indent = "";
#define indent() _indent += " ";
#define dedent() do {if (_indent.size() > 0) _indent = _indent.substr(1);}while(0);

void MyLogDebug(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(0, DebugLog, "", 0, (_indent + fmt).c_str(), args);
	va_end(args);
}
#else
#define indent()
#define dedent()
#define MyLogDebug(...) do {} while(0)
#endif

static size_t TotalStringSize(const StringList& v)
{
	size_t n = 0;
	for (const auto& s : v)
		n += s.size();
	return n;
}


static string JoinNameSegments(const StringList& name)
{
	if (name.empty())
		return {};
	if (name.size() == 1)
		return name[0];

	string out;
	out.reserve(TotalStringSize(name) + (name.size() - 1) * 2);
	out += name[0];
	for (size_t i = 1; i < name.size(); i++)
	{
		out += "::";
		out += name[i];
	}
	return out;
}


static bool TemplateArgsReferenceTemplateParam(const string& raw)
{
	if (raw.empty() || (raw[0] != 'I' && raw[0] != 'J'))
		return false;

	size_t i = 0;
	size_t depth = 0;
	while (i < raw.size())
	{
		char c = raw[i++];
		if (c == 'I' || c == 'J')
		{
			depth++;
			continue;
		}
		if (c == 'E')
		{
			if (depth == 0)
				return false;
			depth--;
			if (depth == 0)
				return false;
			continue;
		}
		if (c == 'T')
			return true;
		if (c >= '0' && c <= '9')
		{
			size_t len = c - '0';
			while (i < raw.size() && raw[i] >= '0' && raw[i] <= '9')
				len = (len * 10) + (raw[i++] - '0');
			i = std::min(raw.size(), i + len);
		}
	}
	return false;
}


static DemangledNamePart NameSegmentWithTemplateArgs(const string& name, vector<DemangledTypeNode::Param> args)
{
	return DemangledNamePart(name, std::move(args), true);
}


static string GetOperator(char elm1, char elm2)
{
	switch (hash(elm1, elm2))
	{
	case hash('d','c'): return "dynamic_cast";
	case hash('s','c'): return "static_cast";
	case hash('c','c'): return "const_cast";
	case hash('r','c'): return "reinterpret_cast";
	case hash('t','i'): return "typeid";
	case hash('t','e'): return "typeid";
	case hash('s','t'): return "sizeof";
	case hash('s','z'): return "sizeof";
	case hash('a','t'): return "alignof";
	case hash('a','z'): return "alignof";
	case hash('a','w'): return "co_await";
	case hash('n','x'): return "noexcept";
	case hash('s','Z'): return "sizeof...";
	case hash('s','P'): return "sizeof...";
	case hash('s','p'): return "";
	case hash('t','w'): return "throw";
	case hash('t','r'): return "throw";
	case hash('l','s'): return "<<";  // <<
	case hash('r','s'): return ">>";  // >>
	case hash('a','S'): return "=";   // =
	case hash('n','t'): return "!";   // !
	case hash('e','q'): return "==";  // ==
	case hash('n','e'): return "!=";  // !=
	case hash('i','x'): return "[]";  // []
	case hash('d','t'): return ".";   // .
	case hash('p','t'): return "->";  // ->
	case hash('m','l'): return "*";   // *
	case hash('p','p'): return "++";  // ++ (postfix in <expression> context)
	case hash('m','m'): return "--";  // -- (postfix in <expression> context)
	case hash('n','g'): return "-";   // - (unary)
	case hash('m','i'): return "-";   // -
	case hash('p','s'): return "+";   // + (unary)
	case hash('p','l'): return "+";   // +
	case hash('a','d'): return "&";   // & (unary)
	case hash('a','n'): return "&";   // &
	case hash('p','m'): return "->*"; // ->*
	case hash('d','v'): return "/";   // /
	case hash('r','m'): return "%";   // %
	case hash('l','t'): return "<";   // <
	case hash('l','e'): return "<=";  // <=
	case hash('g','t'): return ">";   // >
	case hash('g','e'): return ">=";  // >=
	case hash('c','m'): return ",";   // ,
	case hash('c','l'): return "()";  // ()
	case hash('c','o'): return "~";   // ~
	case hash('e','o'): return "^";   // ^
	case hash('o','r'): return "|";   // |
	case hash('a','a'): return "&&";  // &&
	case hash('o','o'): return "||";  // ||
	case hash('d','e'): return "*";   // * (unary)
	case hash('m','L'): return "*=";  // *=
	case hash('p','L'): return "+=";  // +=
	case hash('m','I'): return "-=";  // -=
	case hash('d','V'): return "/=";  // /=
	case hash('r','M'): return "%=";  // %=
	case hash('r','S'): return ">>="; // >>=
	case hash('l','S'): return "<<="; // <<=
	case hash('a','N'): return "&=";  // &=
	case hash('o','R'): return "|=";  // |=
	case hash('e','O'): return "^=";  // ^=
	case hash('s','s'): return "<=>"; // <=>
	case hash('d','l'): return "delete";   // delete
	case hash('d','a'): return "delete[]"; // delete[]
	case hash('n','w'): return "new";      // new
	case hash('n','a'): return "new[]";    // new []
	default: return "";
	}
}

static BNNameType GetNameType(char elm1, char elm2)
{
	switch (hash(elm1, elm2))
	{
	case hash('n','t'): return OperatorNotNameType;              // !
	case hash('n','g'): return OperatorMinusNameType;       // - (unary)
	case hash('p','s'): return OperatorPlusNameType;        // + (unary)
	case hash('a','d'): return OperatorBitAndNameType;      // & (unary)
	case hash('d','e'): return OperatorStarNameType;        // * (unary)
	case hash('i','x'): return OperatorArrayNameType;            // []
	case hash('p','p'): return OperatorIncrementNameType;        // ++ (postfix in <expression> context)
	case hash('m','m'): return OperatorDecrementNameType;        // -- (postfix in <expression> context)
	case hash('l','s'): return OperatorLeftShiftNameType;        // <<
	case hash('r','s'): return OperatorRightShiftNameType;       // >>
	case hash('a','S'): return OperatorAssignNameType;           // =
	case hash('e','q'): return OperatorEqualNameType;            // ==
	case hash('n','e'): return OperatorNotEqualNameType;         // !=
	case hash('p','t'): return OperatorArrowNameType;            // ->
	case hash('m','l'): return OperatorStarNameType;             // *
	case hash('m','i'): return OperatorMinusNameType;            // -
	case hash('p','l'): return OperatorPlusNameType;             // +
	case hash('a','n'): return OperatorBitAndNameType;           // &
	case hash('p','m'): return OperatorArrowStarNameType;        // ->*
	case hash('d','v'): return OperatorDivideNameType;           // /
	case hash('r','m'): return OperatorModulusNameType;          // %
	case hash('l','t'): return OperatorLessThanNameType;         // <
	case hash('l','e'): return OperatorLessThanEqualNameType;    // <=
	case hash('g','t'): return OperatorGreaterThanNameType;      // >
	case hash('g','e'): return OperatorGreaterThanEqualNameType; // >=
	case hash('c','m'): return OperatorCommaNameType;           // ,
	case hash('c','l'): return OperatorParenthesesNameType;     // ()
	case hash('c','o'): return OperatorTildeNameType;           // ~
	case hash('e','o'): return OperatorXorNameType;             // ^
	case hash('o','r'): return OperatorBitOrNameType;           // |
	case hash('a','a'): return OperatorLogicalAndNameType;      // &&
	case hash('o','o'): return OperatorLogicalOrNameType;       // ||
	case hash('m','L'): return OperatorStarEqualNameType;       // *=
	case hash('p','L'): return OperatorPlusEqualNameType;       // +=
	case hash('m','I'): return OperatorMinusEqualNameType;      // -=
	case hash('d','V'): return OperatorDivideEqualNameType;     // /=
	case hash('r','M'): return OperatorModulusEqualNameType;    // %=
	case hash('r','S'): return OperatorRightShiftEqualNameType; // >>=
	case hash('l','S'): return OperatorLeftShiftEqualNameType;  // <<=
	case hash('a','N'): return OperatorAndEqualNameType;        // &=
	case hash('o','R'): return OperatorOrEqualNameType;         // |=
	case hash('e','O'): return OperatorXorEqualNameType;        // ^=
	case hash('d','l'): return OperatorDeleteNameType;          // delete
	case hash('d','a'): return OperatorDeleteArrayNameType;     // delete[]
	case hash('n','w'): return OperatorNewNameType;             // new
	case hash('n','a'): return OperatorNewArrayNameType;        // new []
	// Note: C1-C5 (constructor) and D0-D5 (destructor) are handled directly
	// by DemangleUnqualifiedName with their own case blocks, so they never
	// reach GetNameType.
	default:
		return NoNameType;
	}
}




// Decode a big-endian hex string into a float or double.
// Returns the decimal string representation, or the raw hex with a type
// prefix if decoding fails or the result is NaN/Inf.
static string DecodeHexFloat(const string& hex, size_t byteCount)
{
	if (hex.size() != byteCount * 2)
		return hex;

	// Parse big-endian hex into an integer, then reinterpret as float/double
	uint64_t bits = 0;
	for (size_t i = 0; i < hex.size(); i++)
	{
		char c = hex[i];
		uint64_t nibble;
		if (c >= '0' && c <= '9')      nibble = c - '0';
		else if (c >= 'a' && c <= 'f') nibble = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F') nibble = c - 'A' + 10;
		else return hex;
		bits = (bits << 4) | nibble;
	}

	if (byteCount == 4)
	{
		union { uint32_t i; float f; } u;
		u.i = (uint32_t)bits;
		if (std::isnan(u.f) || std::isinf(u.f))
			return "(float)" + hex;
		return to_string(u.f);
	}
	else if (byteCount == 8)
	{
		union { uint64_t i; double d; } u;
		u.i = bits;
		if (std::isnan(u.d) || std::isinf(u.d))
			return "(double)" + hex;
		return to_string(u.d);
	}
	return hex;
}


// ===== Reader implementation (non-templated) =====

DemangleGNU3Reader::DemangleGNU3Reader(const string& data): m_data(data), m_offset(0)
{}


void DemangleGNU3Reader::Reset(const string& data)
{
	m_data = data;
	m_offset = 0;
}


string DemangleGNU3Reader::PeekString(size_t count)
{
	if (count > Length())
		return "\0";
	return m_data.substr(m_offset, count);
}



#ifdef GNUDEMANGLE_DEBUG
string DemangleGNU3Reader::GetRaw()
{
	return m_data.substr(m_offset);
}
#endif



string DemangleGNU3Reader::ReadString(size_t count)
{
	if (count > Length())
		throw DemangleException();

	const string out = m_data.substr(m_offset, count);
	m_offset += count;
	return out;
}




// ===== DemangleGNU3 implementation =====

DemangleGNU3::DemangleGNU3(Platform* platform, const string& mangledName) :
	m_reader(mangledName),
	m_platform(platform),
	m_lastTypeRef(nullptr),
	m_isParameter(false),
	m_shouldDeleteReader(true),
	m_topLevel(true),
	m_isOperatorOverload(false),
	m_parsingLambdaParams(false),
	m_lambdaTemplateParamBase(0),
	m_permitForwardTemplateRefs(false),
	m_inLocalName(false),
	m_nestingDepth(0)
{
	MyLogDebug("%s : %s\n", __FUNCTION__, m_reader.GetRaw().c_str());
}


DemangleGNU3::NestingGuard::NestingGuard(DemangleGNU3& demangler) : m_demangler(demangler)
{
	m_demangler.m_nestingDepth++;
	if (m_demangler.m_nestingDepth > MAX_DEMANGLE_NESTING_DEPTH)
	{
		m_demangler.m_nestingDepth--;
		throw DemangleException("Detected adversarial mangled string");
	}
}


DemangleGNU3::NestingGuard::~NestingGuard()
{
	m_demangler.m_nestingDepth--;
}


void DemangleGNU3::Reset(Platform* platform, const string& mangledName)
{
	m_reader.Reset(mangledName);
	m_platform = platform;
	m_substitute.clear();
	m_templateSubstitute.clear();
	m_functionSubstitute.clear();
	m_lastTypeRef = nullptr;
	m_lastName.clear();
	m_nameType = {};
	m_localType = {};
	m_hasReturnType = {};
	m_isParameter = false;
	m_shouldDeleteReader = true;
	m_topLevel = true;
	m_isOperatorOverload = false;
	m_parsingLambdaParams = false;
	m_lambdaTemplateParamBase = 0;
	m_permitForwardTemplateRefs = false;
	m_pendingForwardRefs.clear();
	m_inLocalName = false;
	m_nestingDepth = 0;
}


DemangledTypeNode DemangleGNU3::CreateUnknownType(const StringList& s)
{
	return DemangledTypeNode::NamedType(UnknownNamedTypeClass, s);
}


DemangledTypeNode DemangleGNU3::CreateUnknownType(const string& s)
{
	return DemangledTypeNode::NamedType(UnknownNamedTypeClass, StringList{s});
}


static DemangledQualifiedName CopyQualifiedName(const DemangledTypeNode& type)
{
	return type.GetName();
}


void DemangleGNU3::ExtendTypeName(DemangledTypeNode& type, const string& extend)
{
	if (type.GetClass() != NamedTypeReferenceClass)
		return;

	DemangledQualifiedName name = CopyQualifiedName(type);
	if (name.empty())
	{
		name.emplace_back(extend);
		type.SetName(std::move(name));
		return;
	}

	name.back().AppendBase(extend);
	type.SetName(std::move(name));
}


void DemangleGNU3::ApplyTemplateArgs(DemangledTypeNode& type, ParamList args)
{
	if (type.GetClass() != NamedTypeReferenceClass)
		return;

	DemangledQualifiedName qn = CopyQualifiedName(type);
	if (qn.empty())
		qn.emplace_back("");

	qn.back().SetTemplateArguments(std::move(args), true);
	type.SetName(std::move(qn));
}


void DemangleGNU3::AppendTypeName(DemangledTypeNode& type, const DemangledTypeNode& extend)
{
	if (type.GetClass() != NamedTypeReferenceClass)
		return;

	DemangledQualifiedName newName = CopyQualifiedName(type);
	DemangledQualifiedName extendName = CopyQualifiedName(extend);
	newName.reserve(newName.size() + extendName.size());
	newName.insert(newName.end(), extendName.begin(), extendName.end());
	type.SetName(std::move(newName));
}


string DemangleGNU3::LastTypeNameSegmentBase(const DemangledTypeNode& type)
{
	const auto& qn = type.GetName();
	if (!qn.empty())
		return qn.back().GetBase();
	return {};
}


bool DemangleGNU3::LastTypeNameSegmentHasTemplateArguments(const DemangledTypeNode& type)
{
	const auto& qn = type.GetName();
	if (qn.empty())
		return false;
	return qn.back().HasTemplateArguments();
}


DemangleGNU3::NodeRef DemangleGNU3::PushTemplateType(NodeRef type)
{
	if (type)
		m_templateSubstitute.push_back(std::move(type));
	return type;
}


DemangleGNU3::NodeRef DemangleGNU3::PushTemplateType(const DemangledTypeNode& type)
{
	auto ref = DemangledTypeNode::CreateSharedCopy(type);
	m_templateSubstitute.push_back(ref);
	return ref;
}


DemangleGNU3::NodeRef DemangleGNU3::PushTemplateType(DemangledTypeNode&& type)
{
	auto ref = DemangledTypeNode::CreateShared(std::move(type));
	m_templateSubstitute.push_back(ref);
	return ref;
}


#ifdef GNUDEMANGLE_DEBUG
const DemangledTypeNode& DemangleGNU3::GetTemplateType(size_t ref)
{
	if (ref >= m_templateSubstitute.size())
		throw DemangleException();
	if (!m_templateSubstitute[ref])
		throw DemangleException();
	return *m_templateSubstitute[ref];
}
#endif


DemangleGNU3::NodeRef DemangleGNU3::PushType(NodeRef type)
{
	if (type)
		m_substitute.push_back(std::move(type));
	return type;
}


DemangleGNU3::NodeRef DemangleGNU3::PushType(const DemangledTypeNode& type)
{
	auto ref = DemangledTypeNode::CreateSharedCopy(type);
	m_substitute.push_back(ref);
	return ref;
}


DemangleGNU3::NodeRef DemangleGNU3::PushType(DemangledTypeNode&& type)
{
	auto ref = DemangledTypeNode::CreateShared(std::move(type));
	m_substitute.push_back(ref);
	return ref;
}


DemangleGNU3::NodeRef DemangleGNU3::GetTypeRef(size_t ref)
{
	if (ref >= m_substitute.size())
		throw DemangleException();
	if (!m_substitute[ref])
		throw DemangleException();
	return m_substitute[ref];
}


const DemangledTypeNode& DemangleGNU3::GetType(size_t ref)
{
	return *GetTypeRef(ref);
}


#ifdef GNUDEMANGLE_DEBUG
void DemangleGNU3::PrintTables()
{
	LogDebug("Substitution Table\n");
	for (int i = 0; (size_t)i < m_substitute.size(); i++)
	{
		LogDebug("[%d] %s\n", i-1, GetType(i).GetString().c_str());
	}

	LogDebug("Template Table\n");
	for (int i = 0; (size_t)i < m_templateSubstitute.size(); i++)
	{
		LogDebug("[%d] %s\n", i-1, GetTemplateType(i).GetString().c_str());
	}
}
#endif


void DemangleGNU3::DemangleCVQualifiers(bool& cnst, bool& vltl, bool& rstrct)
{
	cnst = false; vltl = false; rstrct = false;
	//[<cv-qualifier>]
	while (1)
	{
		switch (m_reader.Peek())
		{
		case 'r': rstrct = true; break;
		case 'V': vltl = true; break;
		case 'K': cnst = true; break;
		default: return;
		}
		m_reader.Consume(1);
	}
}


string DemangleGNU3::DemangleSourceName()
{
	indent();
	MyLogDebug("%s : %s\n", __FUNCTION__, m_reader.GetRaw().c_str());
	m_lastName = m_reader.ReadString(DemangleNumber());
	dedent();
	return m_lastName;
}


DemangledTypeNode DemangleGNU3::DemangleFunction(bool cnst, bool vltl)
{
	NestingGuard nestingGuard(*this);
	indent();
	MyLogDebug("%s : %s\n", __FUNCTION__, m_reader.GetRaw().c_str());
	bool old_isparam;
	if (m_reader.Peek() == 'Y')
	{
		// TODO: This function is external, should we do anything with that info?
		m_reader.Consume();
	}

	DemangledTypeNode retType = DemangleType();
	NodeRef retTypeRef = m_lastTypeRef;

	ParamList params;
	old_isparam = m_isParameter;
	m_isParameter = true;
	m_functionSubstitute.push_back({});
	[[maybe_unused]] int i = 0;
	while (m_reader.Peek() != 'E')
	{
		DemangledTypeNode param = DemangleType();
		NodeRef paramRef = m_lastTypeRef;
		if (param.GetClass() == VoidTypeClass)
			continue;
		MyLogDebug("Var_%d - %s\n", i++, param.GetString().c_str());
		if (!paramRef)
			paramRef = DemangledTypeNode::CreateShared(std::move(param));
		m_functionSubstitute.back().push_back(paramRef);
		params.push_back({"", paramRef});
	}
	m_reader.Consume();
	m_functionSubstitute.pop_back();
	m_isParameter = old_isparam;
	if (!retTypeRef)
		retTypeRef = DemangledTypeNode::CreateShared(std::move(retType));
	DemangledTypeNode newType = DemangledTypeNode::FunctionType(retTypeRef, nullptr, std::move(params));
	PushType(newType);

	newType.SetConst(cnst);
	newType.SetVolatile(vltl);

	if (cnst || vltl)
		PushType(newType);
	MyLogDebug("After %s : %s\n", __FUNCTION__, m_reader.GetRaw().c_str());
	dedent();
	return newType;
}


void DemangleGNU3::ResolveForwardTemplateRefs(DemangledTypeNode&, const ParamList& args)
{
	if (m_pendingForwardRefs.empty())
		return;
	for (const auto& ref : m_pendingForwardRefs)
	{
		if (!ref.typeRef)
			continue;
		if (ref.index >= args.size() || !args[ref.index].type)
			throw DemangleException();
		*ref.typeRef = *args[ref.index].type;
	}
	m_pendingForwardRefs.clear();
}


DemangledTypeNode DemangleGNU3::DemangleTemplateSubstitution(NodeRef* outTypeRef)
{
	indent();
	MyLogDebug("%s : %s\n", __FUNCTION__, m_reader.GetRaw().c_str());
	if (outTypeRef)
		*outTypeRef = nullptr;
	size_t number = 0;
	char elm = m_reader.Peek();
	if (elm == '_')
	{
		number = 0;
	}
	else if (isdigit(elm))
	{
		size_t n = 0;
		while (isdigit(m_reader.Peek()))
			n = n * 10 + (m_reader.Read() - '0');
		number = n + 1;
	}
	else if (isupper(elm))
	{
		m_reader.Consume();
		number = elm - 'A' + 11;
	}
	else
	{
		throw DemangleException();
	}

	if (m_reader.Read() != '_')
	{
		throw DemangleException();
	}
	dedent();

	if (number < m_templateSubstitute.size())
	{
		if (!m_templateSubstitute[number])
			throw DemangleException();
		if (outTypeRef)
			*outTypeRef = m_templateSubstitute[number];
		return *m_templateSubstitute[number];
	}

	// If forward template references are permitted (e.g. inside a cv conversion
	// operator type), return a shared placeholder node whose contents will be
	// replaced once the outer template args are known.
	if (m_permitForwardTemplateRefs)
	{
		auto typeRef = DemangledTypeNode::CreateShared(CreateUnknownType("auto"));
		m_pendingForwardRefs.push_back({number, typeRef});
		if (outTypeRef)
			*outTypeRef = typeRef;
		return *typeRef;
	}

	if (m_parsingLambdaParams && number >= m_lambdaTemplateParamBase)
	{
		auto typeRef = DemangledTypeNode::CreateShared(CreateUnknownType("auto"));
		if (outTypeRef)
			*outTypeRef = typeRef;
		return *typeRef;
	}

	throw DemangleException();
}


DemangledTypeNode DemangleGNU3::DemangleType()
{
	NestingGuard nestingGuard(*this);
	indent();
	MyLogDebug("%s : %s\n", __FUNCTION__, m_reader.GetRaw().c_str());
	m_lastTypeRef = nullptr;
	DemangledTypeNode type;
	NodeRef typeRef = nullptr;
	bool cnst = false, vltl = false, rstrct = false;
	bool substitute = false;

	DemangleCVQualifiers(cnst, vltl, rstrct);

	if (cnst || vltl || rstrct)
	{
		type = DemangleType();
		if (cnst)
			type.SetConst(true);
		if (vltl)
			type.SetVolatile(true);
		if (rstrct)
			type.SetPointerSuffixBits(1u << RestrictSuffix);
		typeRef = PushType(type);
		m_lastTypeRef = typeRef;
		return type;
	}

	switch(m_reader.Read())
	{
	case 'S':
	{
		if (isdigit(m_reader.Peek()) || m_reader.Peek() == '_' || isupper(m_reader.Peek()))
		{
			type = DemangleSubstitution(&typeRef);
			if (m_reader.Peek() == 'I')
			{
				m_reader.Consume();
				ParamList args;
				DemangleTemplateArgs(args);
				ApplyTemplateArgs(type, std::move(args));
				typeRef = nullptr;
				substitute = true;
			}
		}
		else
		{
			if (m_reader.Peek() == 't')
			{
				m_reader.Consume(1);
				type = DemangleUnqualifiedName();
				auto qn = CopyQualifiedName(type);
				qn.insert(qn.begin(), DemangledNamePart("std"));
				type.SetName(std::move(qn));
				substitute = true;
			}
			else
			{
				type = DemangleSubstitution(&typeRef);
			}
			if (m_reader.Peek() == 'I')
			{
				m_reader.Consume();
				bool dependentTemplatePrefix = LastTypeNameSegmentBase(type) == "basic_ostream" &&
					TemplateArgsReferenceTemplateParam("I" + m_reader.PeekString(m_reader.Length()));
				if (substitute && !dependentTemplatePrefix)
					PushType(type);
				ParamList args;
				DemangleTemplateArgs(args);
				ApplyTemplateArgs(type, std::move(args));
				typeRef = nullptr;
				substitute = true;
			}
		}
		break;
	}
	case 'T':
	{
		/*  <class-enum-type> ::= <name>     # non-dependent type name, dependent type name, or dependent typename-specifier
		                      ::= Ts <name>  # dependent elaborated type specifier using 'struct' or 'class'
		                      ::= Tu <name>  # dependent elaborated type specifier using 'union'
		                      ::= Te <name>  # dependent elaborated type specifier using 'enum'
		*/
		if (m_reader.Peek() == 's')
		{
			m_reader.Consume();
			type = DemangledTypeNode::NamedType(StructNamedTypeClass, StringList{DemangleSourceName()});
			break;
		}
		else if (m_reader.Peek() == 'u')
		{
			m_reader.Consume();
			type = DemangledTypeNode::NamedType(UnionNamedTypeClass, StringList{DemangleSourceName()});
			break;
		}
		else if (m_reader.Peek() == 'e')
		{
			m_reader.Consume();
			type = DemangledTypeNode::NamedTypeWithDefaultIntegerWidth(
				EnumNamedTypeClass, StringList{DemangleSourceName()});
			break;
		}

		//Template Substitution
		type = DemangleTemplateSubstitution(&typeRef);
		// In forward-ref mode (cv conversion operator type parsing), do not consume
		// trailing I<args>E — it belongs to the enclosing nested-name and will be
		// processed by DemangleNestedName's 'I' case, which resolves forward refs.
		substitute = !m_permitForwardTemplateRefs;
		if (!m_permitForwardTemplateRefs && m_reader.Peek() == 'I')
		{
			m_reader.Consume();
			if (substitute)
				PushType(type);
			ParamList args;
			DemangleTemplateArgs(args);
			ApplyTemplateArgs(type, std::move(args));
			typeRef = nullptr;
		}
		break;
	}
	case 'P':
		{
			NodeRef childRef = nullptr;
			DemangledTypeNode child = DemangleType();
			childRef = m_lastTypeRef;
			type = childRef ? DemangledTypeNode::PointerType(childRef, cnst, vltl, PointerReferenceType) :
				DemangledTypeNode::PointerType(std::move(child), cnst, vltl, PointerReferenceType);
			substitute = true;
		break;
	}
	case 'R':
		{
			NodeRef childRef = nullptr;
			DemangledTypeNode child = DemangleType();
			childRef = m_lastTypeRef;
			type = childRef ? DemangledTypeNode::PointerType(childRef, cnst, vltl, ReferenceReferenceType) :
				DemangledTypeNode::PointerType(std::move(child), cnst, vltl, ReferenceReferenceType);
			substitute = true;
		break;
	}
	case 'O':
		{
			NodeRef childRef = nullptr;
			DemangledTypeNode child = DemangleType();
			childRef = m_lastTypeRef;
			type = childRef ? DemangledTypeNode::PointerType(childRef, cnst, vltl, RValueReferenceType) :
				DemangledTypeNode::PointerType(std::move(child), cnst, vltl, RValueReferenceType);
			substitute = true;
		break;
	}
	case 'C': //TODO:complex
	case 'G': //TODO:imaginary
		throw DemangleException();
	case 'U':
	{
		// Vendor-extended type: U <source-name> [<template-args>] <type>
		// Commonly used for Objective-C block pointers:
		//   U13block_pointer <function-type>  ->  "void (params...) block_pointer"
		DemangledNamePart extName(DemangleSourceName());
		if (m_reader.Peek() == 'I')
		{
			m_reader.Consume();
			ParamList targs;
			DemangleTemplateArgs(targs);
			if (!targs.empty())
				extName.SetTemplateArguments(std::move(targs), true);
		}
		DemangledTypeNode inner = DemangleType();
		NodeRef innerRef = m_lastTypeRef ? m_lastTypeRef : DemangledTypeNode::CreateShared(std::move(inner));
		auto extType = DemangledTypeNode::NamedType(UnknownNamedTypeClass, DemangledQualifiedName{std::move(extName)});
		NodeRef extNameRef = DemangledTypeNode::CreateShared(std::move(extType));
		type = DemangledTypeNode::PostfixType(innerRef, " ", extNameRef);
		substitute = true;
		break;
	}
	case 'u':
	{
		// Vendor extended type: u <source-name> [<template-args>]
		// e.g. u14__remove_cvref, u20__remove_reference_t
		DemangledNamePart extName(DemangleSourceName());
		if (m_reader.Peek() == 'I')
		{
			m_reader.Consume();
			ParamList targs;
			DemangleTemplateArgs(targs);
			if (!targs.empty())
				extName.SetTemplateArguments(std::move(targs), true);
		}
		type = DemangledTypeNode::NamedType(UnknownNamedTypeClass, DemangledQualifiedName{std::move(extName)});
		substitute = true;
		break;
	}
	case 'v': type = DemangledTypeNode::VoidType(); break;
	case 'w': type = DemangledTypeNode::WideCharType(4, "wchar_t"); break; //TODO: verify
	case 'b': type = DemangledTypeNode::BoolType(); break;
	case 'c': type = DemangledTypeNode::IntegerType(1, true); break;
	case 'a': type = DemangledTypeNode::IntegerType(1, true, "signed char"); break;
	case 'h': type = DemangledTypeNode::IntegerType(1, false); break;
	case 's': type = DemangledTypeNode::IntegerType(2, true); break;
	case 't': type = DemangledTypeNode::IntegerType(2, false); break;
	case 'i': type = DemangledTypeNode::IntegerType(4, true); break;
	case 'j': type = DemangledTypeNode::IntegerType(4, false); break;
	case 'l': type = DemangledTypeNode::AddressSizedIntegerType(true); break; //long
	case 'm': type = DemangledTypeNode::AddressSizedIntegerType(false); break; //ulong
	case 'x': type = DemangledTypeNode::IntegerType(8, true); break;
	case 'y': type = DemangledTypeNode::IntegerType(8, false); break;
	case 'n': type = DemangledTypeNode::IntegerType(16, true); break;
	case 'o': type = DemangledTypeNode::IntegerType(16, false); break;
	case 'f': type = DemangledTypeNode::FloatType(4); break;
	case 'd': type = DemangledTypeNode::FloatType(8); break;
	case 'e': type = DemangledTypeNode::FloatType(10); break;
	case 'g': type = DemangledTypeNode::FloatType(16); break;
	case 'z': type = DemangledTypeNode::VarArgsType(); break;
	case 'M': // TODO: Make into pointer to function member
	{
		DemangledTypeNode memberName = DemangleType();
		NodeRef memberNameRef = m_lastTypeRef ? m_lastTypeRef : DemangledTypeNode::CreateShared(std::move(memberName));
		DemangledTypeNode member = DemangleType();
		NodeRef memberRef = m_lastTypeRef ? m_lastTypeRef : DemangledTypeNode::CreateShared(std::move(member));
		type = DemangledTypeNode::MemberPointerType(memberRef, CopyQualifiedName(*memberNameRef), cnst, vltl);
		type.SetParenthesizedMemberPointer(true);
		substitute = true;
		break;
	}
	case 'F': type = DemangleFunction(cnst, vltl); break;
	case 'D':
		switch (m_reader.Read())
		{
		case 'd': type = DemangledTypeNode::FloatType(8, "decimal64"); break;
		case 'e': type = DemangledTypeNode::FloatType(16, "decimal128"); break;
		case 'f': type = DemangledTypeNode::FloatType(4, "decimal32"); break;
		case 'h': type = DemangledTypeNode::FloatType(2); break;
		case 'i': type = DemangledTypeNode::WideCharType(4, "char32_t"); break;
		case 's': type = DemangledTypeNode::WideCharType(2, "char16_t"); break;
		case 'a': type = CreateUnknownType("auto"); break; //auto type
		case 'c': type = CreateUnknownType("decltype(auto)"); break; //decltype(auto)
		case 'n':
		{
			static const StringList stdNullptrTName(vector<string>{"std", "nullptr_t"});
			type = CreateUnknownType(stdNullptrTName);
			break;
		}
		case 'p':
		{
			DemangledTypeNode inner = DemangleType();
			NodeRef innerRef = m_lastTypeRef ? m_lastTypeRef : DemangledTypeNode::CreateShared(std::move(inner));
			type = DemangledTypeNode::PostfixType(innerRef, "...");
			break;
		}
		case 't':
		case 'T':
			type = CreateUnknownType("decltype(" + DemangleExpression() + ")");
			if (m_reader.Read() != 'E')
				throw DemangleException();
			break;
		case 'v':
		{
			// vector of size
			uint64_t size = DemangleNumber();
			if (m_reader.Read() != '_')
				throw DemangleException();
			NodeRef childRef = nullptr;
			DemangledTypeNode child = DemangleType();
			childRef = m_lastTypeRef;
			type = childRef ? DemangledTypeNode::ArrayType(childRef, size) :
				DemangledTypeNode::ArrayType(std::move(child), size);
			break;
		}
		default:
			MyLogDebug("Unsupported type: %s:'%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
			throw DemangleException();
		}
		break;
	case 'N':
		type = DemangleNestedName(nullptr, false);
		substitute = true;
		break;
	case 'A':
		//  <array-type> ::= A <positive dimension number> _ <element type>
		//               ::= A [<dimension expression>] _ <element type>
		if (isdigit(m_reader.Peek()))
		{
			//<positive dimension number> _ <element type>
			uint64_t size = DemangleNumber();
			if (m_reader.Read() != '_')
				throw DemangleException();
			NodeRef childRef = nullptr;
			DemangledTypeNode child = DemangleType();
			childRef = m_lastTypeRef;
			type = childRef ? DemangledTypeNode::ArrayType(childRef, size) :
				DemangledTypeNode::ArrayType(std::move(child), size);
		}
		else
		{
			//[<dimension expression>] _ <element type>
			//Since our type system doesn't support expressions as dimensions
			//we preserve the element type node and render a synthetic name at finalization.
			string dimension = "[]";
			if (m_reader.Peek() != '_')
			{
				dimension = "[" + DemangleExpression() + "]";
			}
			if (m_reader.Read() != '_')
				throw DemangleException();

			DemangledTypeNode inner = DemangleType();
			NodeRef innerRef = m_lastTypeRef ? m_lastTypeRef : DemangledTypeNode::CreateShared(std::move(inner));
			type = DemangledTypeNode::PostfixType(innerRef, std::move(dimension));
		}
		substitute = true;
		break;
	default:
	{
		m_reader.UnRead();

		type = DemangleName();
		string lastName = LastTypeNameSegmentBase(type);
		if (lastName.empty())
			throw DemangleException();
		m_lastName = lastName;
		substitute = true;

		if (m_reader.Peek() == 'I')
		{
			substitute = false;
			m_reader.Consume();
			PushType(type);
			ParamList args;
			DemangleTemplateArgs(args);
			ApplyTemplateArgs(type, std::move(args));
			PushType(type);
		}
	}
	}

	if (substitute)
		typeRef = PushType(type);
	m_lastTypeRef = typeRef;

	dedent();
	return type;
}


DemangledTypeNode DemangleGNU3::DemangleSubstitution(NodeRef* outTypeRef)
{
	if (outTypeRef)
		*outTypeRef = nullptr;
	static const StringList stdAllocatorName(vector<string>{"std", "allocator"});
	static const StringList stdBasicStringName(vector<string>{"std", "basic_string"});
	static const StringList stdIostreamName(vector<string>{"std", "iostream"});
	static const StringList stdIstreamName(vector<string>{"std", "istream"});
	static const StringList stdOstreamName(vector<string>{"std", "ostream"});
	static const StringList stdStringName(vector<string>{"std", "string"});
	static const StringList stdName(vector<string>{"std"});

	indent()
	MyLogDebug("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	char elm;
	elm = m_reader.Read();
	StringList name;
	size_t number = 0;
	switch (elm)
	{
	case 'a': name = stdAllocatorName; break;
	case 'b': name = stdBasicStringName; break;
	case 'd': name = stdIostreamName; break;
	case 'i': name = stdIstreamName; break;
	case 'o': name = stdOstreamName; break;
	case 's': name = stdStringName; break;
	case 't': name = stdName; break;
	default:
		if (elm == '_')
		{
			m_reader.UnRead(1);
			number = 0;
		}
		else if (isdigit(elm) || isupper(elm))
		{
			// Seq-id is encoded in base 36 using 0-9 A-Z.
			// The actual substitution index = base36_value + 1.
			// This handles both single-char (S0_ ... SZ_) and
			// multi-char (S10_, S11_, ...) seq-ids.
			size_t base36 = isdigit(elm) ? (size_t)(elm - '0') : (size_t)(elm - 'A' + 10);
			while (m_reader.Peek() != '_')
			{
				char c = m_reader.Read();
				if (isdigit(c))
					base36 = base36 * 36 + (size_t)(c - '0');
				else if (isupper(c))
					base36 = base36 * 36 + (size_t)(c - 'A' + 10);
				else
					throw DemangleException();
			}
			number = base36 + 1;
		}
		else
		{
			// PrintTables();
			throw DemangleException();
		}

		if (m_reader.Read() != '_')
		{
			throw DemangleException();
		}

		dedent();
		auto ref = GetTypeRef(number);
		const DemangledTypeNode& resolved = *ref;
		string lastName = LastTypeNameSegmentBase(resolved);
		if (!lastName.empty())
			m_lastName = lastName;
		if (outTypeRef)
			*outTypeRef = ref;
		return resolved;
	}
	m_lastName = name.back();
	dedent();
	return CreateUnknownType(name);
}

string DemangleGNU3::DemangleNumberAsString()
{
	bool negativeFactor = false;
	if (m_reader.Peek() == 'n')
	{
		negativeFactor = true;
		m_reader.Consume();
	}

	string number;
	while (isdigit(m_reader.Peek()))
	{
		number += m_reader.Read();
	}
	if (negativeFactor)
		return "-" + number;
	return number;
}

// number ::= [n] <decimal>
int64_t DemangleGNU3::DemangleNumber()
{
	bool negative = false;
	if (m_reader.Peek() == 'n')
	{
		negative = true;
		m_reader.Consume();
	}

	if (!isdigit(m_reader.Peek()))
		throw DemangleException();

	int64_t result = 0;
	do
	{
		result = result * 10 + (m_reader.Read() - '0');
	} while (isdigit(m_reader.Peek()));
	return negative ? -result : result;
}


string DemangleGNU3::DemanglePrimaryExpression()
{
	indent();
	MyLogDebug("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	char elm1 = '\0';
	string out;
	StringList tmpList;
	bool oldTopLevel;
	//expr-primary
	if (m_reader.PeekString(2) == "_Z")
	{
		m_reader.Consume(2);
		// The embedded _Z... is an independent mangled name with its own
		// template scope.  Save and clear the template substitution table
		// so inner T_ / T0_ etc. resolve within this symbol, not the outer
		// one.  Set m_topLevel = true so template args get pushed properly.
		auto savedTemplateSubstitute = m_templateSubstitute;
		m_templateSubstitute.clear();
		oldTopLevel = m_topLevel;
		m_topLevel = true;
		DemangledTypeNode t = DemangleSymbol(tmpList);
		m_topLevel = oldTopLevel;
		m_templateSubstitute = std::move(savedTemplateSubstitute);
		out += t.GetTypeAndName(tmpList, m_platform.GetPtr());
		dedent()
		return out;
	}
	// LZ<encoding>E: function address template arg (GCC/Clang, without leading underscore)
	if (m_reader.Peek() == 'Z')
	{
		m_reader.Consume(); // 'Z'
		auto savedTemplateSubstitute2 = m_templateSubstitute;
		m_templateSubstitute.clear();
		oldTopLevel = m_topLevel;
		m_topLevel = true;
		DemangledTypeNode t2 = DemangleSymbol(tmpList);
		m_topLevel = oldTopLevel;
		m_templateSubstitute = std::move(savedTemplateSubstitute2);
		out += t2.GetTypeAndName(tmpList, m_platform.GetPtr());
		dedent();
		return out;
	}
	switch (m_reader.Read())
	{
	case 'b':
		elm1 = m_reader.Read();
		if (elm1 == '0')
			out += "false";
		else if (elm1 == '1')
			out += "true";
		else
			throw DemangleException();
		break;
	case 'd': //double (16 hex chars = 8 bytes)
		out += DecodeHexFloat(m_reader.ReadString(16), 8);
		break;
	case 'e': //long double (20 hex chars = 10 bytes, platform-dependent layout)
		out += "(long double)" + m_reader.ReadString(20);
		break;
	case 'f': //float (8 hex chars = 4 bytes)
		out += DecodeHexFloat(m_reader.ReadString(8), 4);
		break;
	case 'g': //float_128 (32 hex chars = 16 bytes)
		out += "(__float128)" + m_reader.ReadString(32);
		break;
	case 'l': out = DemangleNumberAsString() + "l"; break;  //long
	case 'x': out = DemangleNumberAsString() + "ll"; break;  //long long
	case 's': out = "(short)" + DemangleNumberAsString(); break; //short
	case 'n': out = "(__int128)" + DemangleNumberAsString(); break;  //__int128
	case 'i': out = DemangleNumberAsString(); break;       // int
	case 'm': out = DemangleNumberAsString() + "ul"; break;  //unsigned long
	case 't': out = "(unsigned short)" + DemangleNumberAsString(); break; //unsigned short
	case 'y': out = DemangleNumberAsString() + "ull"; break;  //unsigned long long
	case 'j': out = DemangleNumberAsString() + "u"; break; // unsigned int
		break;
	default:
	{
		m_reader.UnRead(1);
		const string castType = DemangleTypeString();
		const string castVal = DemangleNumberAsString();
		out = "(" + castType + ")" + castVal;
		break;
	}
	}
	if (m_reader.Read() != 'E')
		throw DemangleException();

	dedent();
	return out;
}


string DemangleGNU3::DemangleUnarySuffixExpression(const string& op)
{
	return "(" + DemangleExpression() + ")" + op;
}


string DemangleGNU3::DemangleUnaryPrefixExpression(const string& op)
{
	return op + "(" + DemangleExpression() + ")";
}


string DemangleGNU3::DemangleBinaryExpression(const string& op)
{
	indent();
	MyLogDebug("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	const string lhs = "(" + DemangleExpression() + ")";
	const string rhs = "(" + DemangleExpression() + ")";
	dedent();
	return lhs + " " + op + " " + rhs;
}


string DemangleGNU3::DemangleUnaryPrefixType(const string& op)
{
	return op + "(" + DemangleTypeString() + ")";
}


string DemangleGNU3::DemangleTypeString()
{
	return DemangleType().GetString();
}


string DemangleGNU3::DemangleExpressionList()
{
	indent();
	MyLogDebug("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	string expr;
	bool first = true;
	m_functionSubstitute.push_back({});
	while (m_reader.Peek() != 'E')
	{
		if (!first)
			expr += ", ";
		const string e = DemangleExpression();
		expr += e;
		m_functionSubstitute.back().push_back(DemangledTypeNode::CreateShared(CreateUnknownType(e)));
		first = false;
	}
	m_functionSubstitute.pop_back();
	m_reader.Consume();
	dedent();
	return expr;
}


DemangledTypeNode DemangleGNU3::DemangleUnqualifiedName()
{
	indent()
	MyLogDebug("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());

	DemangledTypeNode outType;
	char elm1 = m_reader.Read();
	char elm2 = m_reader.Read();
	switch (hash(elm1, elm2))
	{
	case hash('n','t'): // !
	case hash('n','g'): // - (unary)
	case hash('p','s'): // + (unary)
	case hash('a','d'): // & (unary)
	case hash('d','e'): // * (unary)
	case hash('i','x'): // []
	case hash('p','p'): // ++ (postfix in <expression> context)
	case hash('m','m'): // -- (postfix in <expression> context)
	case hash('l','s'): // <<
	case hash('r','s'): // >>
	case hash('a','S'): // =
	case hash('e','q'): // ==
	case hash('n','e'): // !=
	case hash('p','t'): // ->
	case hash('d','t'): // .
	case hash('m','l'): // *
	case hash('m','i'): // -
	case hash('p','l'): // +
	case hash('a','n'): // &
	case hash('p','m'): // ->*
	case hash('d','v'): // /
	case hash('r','m'): // %
	case hash('l','t'): // <
	case hash('l','e'): // <=
	case hash('g','t'): // >
	case hash('g','e'): // >=
	case hash('c','m'): // ,
	case hash('c','l'): // ()
	case hash('c','o'): // ~
	case hash('e','o'): // ^
	case hash('o','r'): // |
	case hash('a','a'): // &&
	case hash('o','o'): // ||
	case hash('m','L'): // *=
	case hash('p','L'): // +=
	case hash('m','I'): // -=
	case hash('d','V'): // /=
	case hash('r','M'): // %=
	case hash('r','S'): // >>=
	case hash('l','S'): // <<=
	case hash('a','N'): // &=
	case hash('o','R'): // |=
	case hash('e','O'): // ^=
	case hash('s','s'): // <=>
		outType = CreateUnknownType("operator" + GetOperator(elm1, elm2));
		outType.SetNameType(GetNameType(elm1, elm2));
		break;
	case hash('t','i'):
	case hash('t','e'):
	case hash('s','t'):
	case hash('s','z'):
	case hash('a','t'):
	case hash('a','z'):
	case hash('a','w'):
	case hash('n','x'):
	case hash('s','Z'):
	case hash('s','P'):
	case hash('s','p'):
	case hash('d','l'): // delete
	case hash('d','a'): // delete[]
	case hash('n','w'): // new
	case hash('n','a'): // new []
		outType = CreateUnknownType("operator " + GetOperator(elm1, elm2));
		outType.SetNameType(GetNameType(elm1, elm2));
		break;
	case hash('v','0'):
	case hash('v','1'):
	case hash('v','2'):
	case hash('v','3'):
	case hash('v','4'):
	case hash('v','5'):
	case hash('v','6'):
	case hash('v','7'):
	case hash('v','8'):
	case hash('v','9'):
		//TODO: Unsupported vendor extended types
		throw DemangleException();
	case hash('C','1'): //Construtor
	case hash('C','2'):
	case hash('C','3'):
	case hash('C','4'):
	case hash('C','5'):
		outType = CreateUnknownType(m_lastName);
		outType.SetNameType(ConstructorNameType);
		break;
	case hash('C','I'): // Inheriting constructor: CI1 <type> or CI2 <type>
	{
		char kind = m_reader.Read(); // '1' or '2'
		if (kind != '1' && kind != '2')
			throw DemangleException();
		// Save m_lastName: parsing the inherited-class type will overwrite it
		string savedLastName = m_lastName;
		DemangleType();
		m_lastName = savedLastName;
		outType = CreateUnknownType(m_lastName);
		outType.SetNameType(ConstructorNameType);
		break;
	}
	case hash('D','0'): //Destructor
	case hash('D','1'):
	case hash('D','2'):
	case hash('D','3'):
	case hash('D','4'):
	case hash('D','5'):
		outType = CreateUnknownType("~" + m_lastName);
		outType.SetNameType(DestructorNameType);
		break;
	case hash('D','t'):
	case hash('D','T'):
		outType = CreateUnknownType(DemangleExpression());
		// if (m_reader.Read() != 'E')
		// 	throw DemangleException();
		break;
	case hash('U','l'): //Lambda
	{
		string name;
		name = "'lambda";
		vector<DemangledTypeNode> lambdaParams;
		// Generic lambdas encode 'auto' params as template params. Preserve any
		// enclosing template substitutions, and synthesize lambda-local autos
		// lazily only when a template-param reference does not resolve.
		bool savedParsingLambdaParams = m_parsingLambdaParams;
		size_t savedLambdaTemplateParamBase = m_lambdaTemplateParamBase;
		m_parsingLambdaParams = true;
		m_lambdaTemplateParamBase = m_templateSubstitute.size();
		do
		{
			DemangledTypeNode param = DemangleType();
			if (param.GetClass() == VoidTypeClass)
				break;
			lambdaParams.push_back(std::move(param));
		}while (m_reader.Peek() != 'E');
		m_reader.Consume();
		m_parsingLambdaParams = savedParsingLambdaParams;
		m_lambdaTemplateParamBase = savedLambdaTemplateParamBase;

		if (isdigit(m_reader.Peek()))
		{
			name += DemangleNumberAsString();
		}
		if (m_reader.Read() != '_')
			throw DemangleException();

		name += "'(";
		for (size_t i = 0; i < lambdaParams.size(); i++)
		{
			if (i != 0)
				name += ", ";
			name += lambdaParams[i].GetString();
		}
		name += ")";
		m_lastName = name;
		outType = CreateUnknownType(name);
		PushType(outType);
		break;
	}
	case hash('U','t'):
	{
		string name;
		name = "'unnamed";

		if (isdigit(m_reader.Peek()))
		{
			name += DemangleNumberAsString();
		}
		name += "\'";

		if (m_reader.Read() != '_')
			throw DemangleException();

		m_lastName = name;
		outType = CreateUnknownType(name);
		break;
	}
	case hash('c','v'): //type (expression)
	{
		// The conversion operator type may reference template params (T_, T0_, ...)
		// that aren't yet in m_templateSubstitute (they're defined by a following
		// I<args>E in the enclosing nested name).  Set m_permitForwardTemplateRefs so
		// that DemangleTemplateSubstitution() returns a shared placeholder instead of
		// throwing, and don't consume trailing I<args>E in the T case of DemangleType.
		// The outer DemangleNestedName case 'I' will parse those args and call
		// ResolveForwardTemplateRefs() to replace those placeholders with the real args.
		bool savedPermit = m_permitForwardTemplateRefs;
		m_pendingForwardRefs.clear();
		m_permitForwardTemplateRefs = true;
		DemangledTypeNode cvType = DemangleType();
		NodeRef cvTypeRef = m_lastTypeRef ? m_lastTypeRef : DemangledTypeNode::CreateShared(std::move(cvType));
		m_permitForwardTemplateRefs = savedPermit;
		outType = DemangledTypeNode::NamedType(UnknownNamedTypeClass,
			DemangledQualifiedName{DemangledNamePart("operator ", std::move(cvTypeRef))});
		break;
	}
	default:
		m_reader.UnRead(2);
		if (isdigit(m_reader.Peek()) || m_reader.Read() == 'L')
		{
			string name = DemangleSourceName();
			if (name.size() > 11 && name.substr(0, 11) == "_GLOBAL__N_")
				name = "(anonymous namespace)";
			m_lastName = name;
			outType = CreateUnknownType(name);
		}
		else
		{
			throw DemangleException();
		}
	}
	// Consume ABI tags: B <source-name>  =>  [abi:tagname]
	// Applies to source names, operator names, and unnamed types.
	while (m_reader.Peek() == 'B')
	{
		m_reader.Consume();
		string tag = "[abi:" + DemangleSourceName() + "]";
		ExtendTypeName(outType, tag);
		string lastName = LastTypeNameSegmentBase(outType);
		m_lastName = lastName.empty() ? tag : lastName;
	}
	dedent();
	return outType;
}


StringList DemangleGNU3::DemangleBaseUnresolvedName()
{
	// <base-unresolved-name> ::= <simple-id>                                # unresolved name
	//                        ::= on <operator-name>                         # unresolved operator-function-id
	//                        ::= on <operator-name> <template-args>         # unresolved operator template-id
	//                        ::= dn <destructor-name>                       # destructor or pseudo-destructor;
	//                                                                       # e.g. ~X or ~X<N-1>

	indent()
	MyLogDebug("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	StringList out;
	if (m_reader.Length() > 1)
	{
		const string str = m_reader.PeekString(2);
		if (str == "on")
		{
			m_reader.Consume(); m_reader.Consume(); // skip 'o','n' prefix
			char op1 = m_reader.Read();
			char op2 = m_reader.Read();
			out.push_back(GetOperator(op1, op2));
			if (m_reader.Peek() == 'I')
			{
				m_reader.Consume();
				ParamList args;
				DemangleTemplateArgs(args);
				out.back() = NameSegmentWithTemplateArgs(out.back(), std::move(args)).GetString();
				PushType(CreateUnknownType(out));
			}
		}
		else if (str == "dn")
		{
			string name = DemangleUnresolvedType().GetString();
			if (name.empty())
				out.push_back("~" + DemangleSourceName());
			else
				out.push_back("~" + name);
		}
		else
		{
			// <simple-id>
			out.push_back(DemangleSourceName());
			if (m_reader.Peek() == 'I')
			{
				m_reader.Consume();
				ParamList args;
				DemangleTemplateArgs(args);
				out.back() = NameSegmentWithTemplateArgs(out.back(), std::move(args)).GetString();
			}
		}
	}
	dedent();
	return out;
}


DemangledTypeNode DemangleGNU3::DemangleUnresolvedType()
{
	indent();
	MyLogDebug("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	//<unresolved-type> ::= <template-param> [ <template-args> ]            # T:: or T<X,Y>::
	//                  ::= <decltype>                                      # decltype(p)::
	//                  ::= <substitution>
	DemangledTypeNode type;
	if (m_reader.Peek() == 'T')
	{
		m_reader.Consume();
		type = DemangleTemplateSubstitution();
		if (m_reader.Peek() == 'I')
		{
			PushType(type);
			m_reader.Consume();
			ParamList args;
			DemangleTemplateArgs(args);
			ApplyTemplateArgs(type, std::move(args));
			PushType(type);
		}
		else
		{
			// Template param used as scope qualifier (e.g. sr T_ name) is a substitution
			// candidate: the compiler adds it to the main sub table so subsequent
			// occurrences can use Sn_ instead of T_.
			PushType(type);
		}
	}
	else if (m_reader.Length() > 2 && (m_reader.PeekString(2) == "Dt" || m_reader.PeekString(2) == "DT"))
	{
		m_reader.Consume(); // 'D'
		m_reader.Consume(); // 't' or 'T'
		const string name = "decltype(" + DemangleExpression() + ")";
		if (m_reader.Read() != 'E')
			throw DemangleException();
		type = CreateUnknownType(name);
	}
	else if (m_reader.Peek() == 'S')
	{
		m_reader.Consume();
		type = DemangleSubstitution();
	}
	else
	{
		throw DemangleException();
	}
	dedent();
	return type;
}


string DemangleGNU3::DemangleExpression()
{
	MyLogDebug("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	/*
	<expression> ::= <unary operator-name> <expression>
	               ::= <binary operator-name> <expression> <expression>
	               ::= <ternary operator-name> <expression> <expression> <expression>
	               ::= pp_ <expression>                                     # prefix ++
	               ::= mm_ <expression>                                     # prefix --
	               ::= cl <expression>+ E                                   # expression (expr-list), call
	               ::= cv <type> <expression>                               # type (expression), conversion with one argument
	               ::= cv <type> _ <expression>* E                          # type (expr-list), conversion with other than one argument
	               ::= tl <type> <expression>* E                            # type {expr-list}, conversion with braced-init-list argument
	               ::= il <expression> E                                    # {expr-list}, braced-init-list in any other context
	               ::= [gs] nw <expression>* _ <type> E                     # new (expr-list) type
	               ::= [gs] nw <expression>* _ <type> <initializer>         # new (expr-list) type (init)
	               ::= [gs] na <expression>* _ <type> E                     # new[] (expr-list) type
	               ::= [gs] na <expression>* _ <type> <initializer>         # new[] (expr-list) type (init)
	               ::= [gs] dl <expression>                                 # delete expression
	               ::= [gs] da <expression>                                 # delete[] expression
	               ::= dc <type> <expression>                               # dynamic_cast<type> (expression)
	               ::= sc <type> <expression>                               # static_cast<type> (expression)
	               ::= cc <type> <expression>                               # const_cast<type> (expression)
	               ::= rc <type> <expression>                               # reinterpret_cast<type> (expression)
	               ::= ti <type>                                            # typeid (type)
	               ::= te <expression>                                      # typeid (expression)
	               ::= st <type>                                            # sizeof (type)
	               ::= sz <expression>                                      # sizeof (expression)
	               ::= at <type>                                            # alignof (type)
	               ::= az <expression>                                      # alignof (expression)
	               ::= nx <expression>                                      # noexcept (expression)
	               ::= <template-param>
	               ::= <function-param>
	               ::= dt <expression> <unresolved-name>                    # expr.name
	               ::= pt <expression> <unresolved-name>                    # expr->name
	               ::= ds <expression> <expression>                         # expr.*expr
	               ::= sZ <template-param>                                  # sizeof...(T), size of a template parameter pack
	               ::= sZ <function-param>                                  # sizeof...(parameter), size of a function parameter pack
	               ::= sP <template-arg>* E                                 # sizeof...(T), size of a captured template parameter pack from an alias template
	               ::= sp <expression>                                      # expression..., pack expansion
	               ::= tw <expression>                                      # throw expression
	               ::= tr                                                   # throw with no operand (rethrow)
	               ::= <unresolved-name>                                    # f(p), N::f(p), ::f(p),
	                                                                        # freestanding dependent name (e.g., T::x),
	                                                                        # objectless nonstatic member reference
	               ::= <expr-primary>
	*/
	char elm1 = '\0', elm2 = '\0';
	string gs, out;
	elm1 = m_reader.Read();
	if (elm1 == 'L')
	{
		out = DemanglePrimaryExpression();
		return out;
	}
	else if (elm1 == 'T') //<template-param>
	{
		return DemangleTemplateSubstitution().GetString();
	}

	elm2 = m_reader.Read();
	if (hash(elm1, elm2) == hash('g', 's'))
	{
		elm1 = m_reader.Read();
		elm2 = m_reader.Read();
		switch (hash(elm1, elm2))
		{
		case hash('s','r'):
		case hash('n','w'):
		case hash('n','a'):
		case hash('d','l'):
		case hash('d','a'): break;
		default:
			throw DemangleException();
		}
		gs = "::";
	}

	switch (hash(elm1, elm2))
	{
	case hash('d','c'):
	case hash('s','c'):
	case hash('c','c'):
	case hash('r','c'):
	{
		const string op = GetOperator(elm1, elm2);
		const string castType = DemangleTypeString();
		const string castExpr = DemangleExpression();
		return op + "<" + castType + ">(" + castExpr + ")";
	}
	case hash('t','i'):
	case hash('t','e'):
	case hash('s','t'):
	case hash('s','z'):
	case hash('a','t'):
	case hash('a','z'):
	case hash('n','x'):
		return GetOperator(elm1, elm2) + "(" + DemangleTypeString() + ")";
	case hash('s','Z'):
		return GetOperator(elm1, elm2) + "(" + DemangleTypeString() + ")";
	case hash('s','P'):
	{
		ParamList args;
		DemangleTemplateArgs(args);
		return "sizeof...(" + NameSegmentWithTemplateArgs("", std::move(args)).GetString() + ")...";
	}
	case hash('s','p'):
		return "(" + DemangleExpression() + ")...";
	case hash('t','w'):
		return GetOperator(elm1, elm2) + DemangleExpression();
	case hash('t','r'):
		return GetOperator(elm1, elm2); //rethrow
	case hash('n','t'): // !
	case hash('n','g'): // - (unary)
	case hash('p','s'): // + (unary)
	case hash('a','d'): // & (unary)
	case hash('d','e'): // * (unary)
		return DemangleUnaryPrefixExpression(GetOperator(elm1, elm2));
	case hash('i','x'): // []
	case hash('p','p'): // ++ (postfix in <expression> context)
	case hash('m','m'): // -- (postfix in <expression> context)
		return DemangleUnarySuffixExpression(GetOperator(elm1, elm2));
	case hash('d','t'): // .
	{
		const string dtObj = DemangleExpression();
		const string dtMem = DemangleExpression();
		return dtObj + "." + dtMem;
	}
	case hash('p','t'): // ->
	{
		const string ptObj = DemangleExpression();
		const string ptMem = DemangleExpression();
		return ptObj + "->" + ptMem;
	}
	case hash('l','s'): // <<
	case hash('r','s'): // >>
	case hash('a','S'): // =
	case hash('e','q'): // ==
	case hash('n','e'): // !=
	case hash('m','l'): // *
	case hash('m','i'): // -
	case hash('p','l'): // +
	case hash('a','n'): // &
	case hash('p','m'): // ->*
	case hash('d','v'): // /
	case hash('r','m'): // %
	case hash('l','t'): // <
	case hash('l','e'): // <=
	case hash('g','t'): // >
	case hash('g','e'): // >=
	case hash('c','m'): // ,
	case hash('c','o'): // ~
	case hash('e','o'): // ^
	case hash('o','r'): // |
	case hash('a','a'): // &&
	case hash('o','o'): // ||
	case hash('m','L'): // *=
	case hash('p','L'): // +=
	case hash('m','I'): // -=
	case hash('d','V'): // /=
	case hash('r','M'): // %=
	case hash('r','S'): // >>=
	case hash('l','S'): // <<=
	case hash('a','N'): // &=
	case hash('o','R'): // |=
	case hash('e','O'): // ^=
		return DemangleBinaryExpression(GetOperator(elm1, elm2));
	case hash('d','l'): // delete
	case hash('d','a'): // delete[]
	case hash('n','w'): // new
	case hash('n','a'): // new []
		return gs + DemangleUnaryPrefixType(GetOperator(elm1, elm2));
	case hash('q','u'): // ternary
	{
		const string cond = DemangleExpression();
		const string then_expr = DemangleExpression();
		const string else_expr = DemangleExpression();
		return cond + "?" + then_expr + ":" + else_expr;
	}
	case hash('c','l'): // ()
	{
		const string callable = DemangleExpression();
		string args;
		bool firstArg = true;
		m_functionSubstitute.push_back({});
		while (m_reader.Peek() != 'E')
		{
			if (!firstArg) args += ", ";
			const string e = DemangleExpression();
			args += e;
			m_functionSubstitute.back().push_back(DemangledTypeNode::CreateShared(CreateUnknownType(e)));
			firstArg = false;
		}
		m_functionSubstitute.pop_back();
		m_reader.Consume(); // 'E'
		return callable + "(" + args + ")";
	}
	case hash('c','v'): //type (expression)
	{
		DemangledTypeNode type = DemangleType();
		out = type.GetString();
		if (m_reader.Peek() == '_')
		{
			m_reader.Consume(); // consume '_' delimiter before expression list
			out += " (" + DemangleExpressionList() + ")";
		}
		else
			out += " (" + DemangleExpression() + ")";
		return out;
	}
	case hash('t','l'): //type {expression}
	{
		const string tlType = DemangleTypeString();
		const string tlExprs = DemangleExpressionList();
		return tlType + " {" + tlExprs + "}";
	}
	case hash('i', 'l'): //{expr-list}, braced-init-list in any other context
		out = DemangleExpression();
		if (m_reader.Read() != 'E')
			throw DemangleException();
		return out;
	case hash('f','p'):
	case hash('f','L'):
	{
		//<function-param> ::= fp <CV> _                         # L == 0, first parameter
		//                 ::= fp <CV> <prm-2 num> _             # L == 0, second and later parameters
		//                 ::= fL <L-1 num> p <CV> _             # L  > 0, first parameter
		//                 ::= fL <L-1 num> p <CV> <prm-2 num> _ # L  > 0, second and later parameters

		bool cnst = false, vltl = false, rstrct = false;
		DemangledTypeNode type;
		int64_t listNumber = 0;
		int64_t elementNum = 0;
		char elm;
		if (elm2 == 'L')
		{
			// fL <L-1 num> p <CV> [<prm-2 num>] _
			// When listNumber is out of range (e.g. fL used inside a decltype return
			// type before function params are known), the fallback paths below produce
			// a placeholder string "fp" / "fpN".
			listNumber = DemangleNumber() + 1;
			if (listNumber < 0 || m_reader.Read() != 'p')
				throw DemangleException();
		}
		DemangleCVQualifiers(cnst, vltl, rstrct);
		elm = m_reader.Peek();
		if (elm == '_')
		{
			m_reader.Consume(1);
			if ((uint64_t)listNumber >= (uint64_t)m_functionSubstitute.size() ||
			    (size_t)elementNum >= m_functionSubstitute[listNumber].size())
			{
				// fp_ used before params are known (e.g., in decltype return type)
				out = (elementNum == 0) ? "fp" : "fp" + std::to_string(elementNum - 1);
				break;
			}
			if (!m_functionSubstitute[listNumber][elementNum])
				throw DemangleException();
			type = *m_functionSubstitute[listNumber][elementNum];
		}
		else if (isdigit(elm) || isupper(elm))
		{
			elementNum = DemangleNumber() + 1;
			if (m_reader.Read() != '_')
				throw DemangleException();
			if (elementNum < 0 ||
			    (uint64_t)listNumber >= (uint64_t)m_functionSubstitute.size() ||
			    (size_t)elementNum >= m_functionSubstitute[listNumber].size())
			{
				// fpN_ used before params are known
				out = "fp" + std::to_string(elementNum - 1);
				break;
			}
			if (!m_functionSubstitute[listNumber][elementNum])
				throw DemangleException();
			type = *m_functionSubstitute[listNumber][elementNum];
		}
		else
		{
			throw DemangleException();
		}
		out = type.GetString();
		break;
	}
	case hash('s','r'):
		/*
		<unresolved-name> ::=
		                  ::=   <unresolved-type> <base-unresolved-name>                  # T::x / decltype(p)::x
		                  ::= N <unresolved-type> <unresolved-qualifier-level>+ E <base-unresolved-name>
		                                                                                    # T::N::x /decltype(p)::N::x
		                  ::=                     <unresolved-qualifier-level>+ E <base-unresolved-name>
		                                                            # A::x, N::y, A<T>::z; "gs" means leading "::"

		<unresolved-type> ::= <template-param> [ <template-args> ]            # T:: or T<X,Y>::
		                  ::= <decltype>                                      # decltype(p)::
		                  ::= <substitution>

		<unresolved-qualifier-level> ::= <simple-id>
		<base-unresolved-name> ::= <simple-id>                                # unresolved name
		                       ::= on <operator-name>                         # unresolved operator-function-id
		                       ::= on <operator-name> <template-args>         # unresolved operator template-id
		                       ::= dn <destructor-name>                       # destructor or pseudo-destructor;
		                                                                      # e.g. ~X or ~X<N-1>
		*/
		if (m_reader.Peek() == 'N')
		{
			m_reader.Consume();
			// Standard form: N <unresolved-type> <qualifier-levels>+ E <base>
			// where <unresolved-type> is T_, Dt, or S.
			// GCC extension: N <source-name-qualifier>+ E <base>
			// When the first component is a digit (source name), skip the
			// unresolved-type and let the loop below handle all qualifiers.
			if (!isdigit(m_reader.Peek()))
				out += DemangleUnresolvedType().GetString() + "::";
			do
			{
				out += DemangleSourceName();
				// Push bare name (before template args) to substitution table.
				PushType(DemangledTypeNode::NamedType(UnknownNamedTypeClass, StringList{out}));
				if (m_reader.Peek() == 'I')
				{
					ParamList args;
					m_reader.Consume();
					//<tmplate-args>
					DemangleTemplateArgs(args);
					out = NameSegmentWithTemplateArgs(out, std::move(args)).GetString();
					// Also push the template instantiation (name+args).
					PushType(DemangledTypeNode::NamedType(UnknownNamedTypeClass, StringList{out}));
				}
				out += "::";
			}while (m_reader.Peek() != 'E');
			m_reader.Consume();

			out += JoinNameSegments(DemangleBaseUnresolvedName());
			return out;
		}
		if (isdigit(m_reader.Peek()))
		{
			// <unresolved-qualifier-level>+ E <base-unresolved-name>
			// GCC sometimes omits the explicit qualifier-list 'E' when the last
			// qualifier ends with template-args (the template-args 'E' serves double
			// duty). Break out of the loop immediately after any qualifier with
			// template-args rather than waiting for a standalone 'E'.
			//
			// Each qualifier level adds to the substitution table:
			//   - the bare name (before template-args) as a substitution candidate
			//   - the template instantiation (name + args) as another candidate
			// This mirrors how the compiler builds the substitution table during encoding.
			bool hadTemplateArgs = false;
			do
			{
				hadTemplateArgs = false;
				const string segName = DemangleSourceName();
				out += segName;
				// Push bare name to substitution table.
				PushType(CreateUnknownType(out));
				if (m_reader.Peek() == 'I')
				{
					ParamList args;
					m_reader.Consume();
					DemangleTemplateArgs(args); // consumes the trailing 'E'
					out = NameSegmentWithTemplateArgs(out, std::move(args)).GetString();
					// Also push the template instantiation.
					PushType(CreateUnknownType(out));
					hadTemplateArgs = true;
				}
				out += "::";
			}while (!hadTemplateArgs && m_reader.Peek() != 'E');
			// Consume qualifier-list 'E' if present. GCC sometimes omits it when
			// the last qualifier had template-args whose 'E' served double duty,
			// so check rather than unconditionally consuming.
			if (m_reader.Peek() == 'E')
				m_reader.Consume();
			out += JoinNameSegments(DemangleBaseUnresolvedName());
			return out;
		}
		else
		{
			out += DemangleUnresolvedType().GetString() + "::";
			// GCC may encode multi-level scoped names without the 'N' qualifier
			// prefix, e.g. "sr St 6__and_I<T>E 5value" for std::__and_<T>::value.
			// Process any digit-started names: if a name has template args AND
			// another source name follows, it is an intermediate qualifier level;
			// otherwise it is the final base-unresolved-name.
			while (isdigit(m_reader.Peek()))
			{
				const string segName = DemangleSourceName();
				if (m_reader.Peek() == 'I')
				{
					ParamList args;
					m_reader.Consume();
					DemangleTemplateArgs(args);
					if (isdigit(m_reader.Peek()))
					{
						// Another source name follows — intermediate qualifier.
						// Push to the substitution table, mirroring what the
						// N-prefix sr branch does for each nested qualifier.
						string segment = NameSegmentWithTemplateArgs(segName, std::move(args)).GetString();
						PushType(CreateUnknownType(out + segment));
						out += segment + "::";
					}
					else
					{
						// No more source names — this template-id is the final name.
						out += NameSegmentWithTemplateArgs(segName, std::move(args)).GetString();
						return out;
					}
				}
				else
				{
					// Plain source name with no template args — final base name.
					out += segName;
					return out;
				}
			}
			// peek is not a digit: fall back for operator-names ("on") / destructor-names ("dn").
			out += JoinNameSegments(DemangleBaseUnresolvedName());
		}
		return out;
	default:
		m_reader.UnRead(2);
		out = DemangleSourceName();
		if (m_reader.Peek() == 'I')
		{
			ParamList args;
			m_reader.Consume();
			//<tmplate-args>
			DemangleTemplateArgs(args);
			out = NameSegmentWithTemplateArgs(out, std::move(args)).GetString();
		}
		break;
	}
	return out;
}


bool DemangleGNU3::DemangleTemplateArg(ParamList& args, bool* hadNonTypeArg)
{
	DemangledTypeNode tmp;
	NodeRef tmpRef;
	bool tmpValid = false;
	string expr;
	bool topLevel;
	switch (m_reader.Read())
	{
	case 'L':
		expr = DemanglePrimaryExpression();
		tmp = CreateUnknownType(expr);
		tmpRef = DemangledTypeNode::CreateShared(std::move(tmp));
		args.push_back({"", tmpRef});
		tmpValid = true;
		if (hadNonTypeArg) *hadNonTypeArg = true;
		break;
	case 'X':
	{
		DemangledTypeNode exprNode = CreateUnknownType(DemangleExpression());
		args.push_back({"", DemangledTypeNode::CreateShared(std::move(exprNode))});
		if (m_reader.Read() != 'E')
			throw DemangleException();
		if (hadNonTypeArg) *hadNonTypeArg = true;
		break;
	}
	case 'I': // GCC sometimes uses I...E for argument packs instead of J...E
	case 'J':
	{
		size_t prevTemplateSize = m_templateSubstitute.size();
		DemangleTemplateArgs(args, hadNonTypeArg);
		if (m_topLevel && m_templateSubstitute.size() == prevTemplateSize)
			PushTemplateType(CreateUnknownType("auto"));
		break;
	}
	case 'T':
		if (m_reader.Peek() == 'n')
		{
			// <template-arg> ::= <template-param-decl> <template-arg>
			// <template-param-decl> ::= Tn <type>  # non-type parameter
			//
			// The declaration names a synthetic non-type template parameter
			// for the following argument. Binary Ninja does not print those
			// synthetic parameter names, so consume the declaration type and
			// keep only the actual following template argument.
			m_reader.Consume();
			topLevel = m_topLevel;
			m_topLevel = false;
			DemangleType();
			m_topLevel = topLevel;
			return DemangleTemplateArg(args, hadNonTypeArg);
		}
		[[fallthrough]];
	default:
		m_reader.UnRead();
		topLevel = m_topLevel;
		m_topLevel = false;
		tmp = DemangleType();
		m_topLevel = topLevel;
		tmpRef = DemangledTypeNode::CreateShared(std::move(tmp));
		args.push_back({"", tmpRef});
		tmpValid = true;
	}
	if (m_topLevel && tmpValid)
	{
		MyLogDebug("Adding template ref: %s\n", tmpRef ? tmpRef->GetString().c_str() : "");
		PushTemplateType(tmpRef);
	}
	return true;
}


void DemangleGNU3::DemangleTemplateArgs(ParamList& args, bool* hadNonTypeArg)
{
	NestingGuard nestingGuard(*this);
	indent();
	MyLogDebug("%s:: '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	const string lastName = m_lastName;
	while (m_reader.Peek() != 'E')
	{
		if (!DemangleTemplateArg(args, hadNonTypeArg))
			break;
	}
	m_reader.Consume();
	m_lastName = lastName;
	dedent();
	return;
}


DemangledTypeNode DemangleGNU3::DemangleNestedName(bool* allTypeTemplateArgs, bool pushBareTemplatePrefix)
{
	NestingGuard nestingGuard(*this);
	/*
	This can be either a qualified name like: "foo::bar::bas"
	or it can be a qualified type like: "foo::bar::bas & const" thus we return either
	a name or a type.

	<nested-name> ::= N [<CV-qualifiers>] [<ref-qualifier>] <prefix> <unqualified-name> E
	              ::= N [<CV-qualifiers>] [<ref-qualifier>] <template-prefix> <template-args> E

	<prefix> ::= <unqualified-name>                 # global class or namespace
	         ::= <prefix> <unqualified-name>        # nested class or namespace
	         ::= <template-prefix> <template-args>  # class template specialization
	         ::= <template-param>                   # template type parameter
	         ::= <decltype>                         # decltype qualifier
	         ::= <prefix> <data-member-prefix>      # initializer of a data member
	         ::= <substitution>

	<template-prefix> ::= <template unqualified-name>           # global template
	                  ::= <prefix> <template unqualified-name>  # nested template
	                  ::= <template-param>                      # template template parameter
	                  ::= <substitution>

	<unqualified-name> ::= <operator-name>
	                   ::= <ctor-dtor-name>
	                   ::= <source-name>
	                   ::= <unnamed-type-name>

	<source-name> ::= <positive length number> <identifier>
	<identifier>  ::= <unqualified source code identifier>
	*/

	indent();
	MyLogDebug("%s:: '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	DemangledTypeNode type = DemangledTypeNode::NamedType(UnknownNamedTypeClass, StringList{});
	bool cnst = false, vltl = false, rstrct = false;
	bool ref = false;
	bool rvalueRef = false;
	bool substitute = true;
	DemangledTypeNode newType;
	bool base = false;
	bool isTemplate = false;
	//[<CV-qualifiers>]
	DemangleCVQualifiers(cnst, vltl, rstrct);

	//[<ref-qualifier>]
	if (m_reader.Peek() == 'R')
	{
		m_reader.Consume();
		ref = true;
	}
	else if (m_reader.Peek() == 'O')
	{
		m_reader.Consume();
		ref = true;
		rvalueRef = true;
	}

	while (m_reader.Peek() != 'E')
	{
		isTemplate = false;
		substitute = true;
		size_t startSize = m_templateSubstitute.size();
		switch (m_reader.Read())
		{
		case 'M': // <data-member-prefix>: closure/lambda inside a data member initializer
			// 'M' follows the member name and marks that subsequent components are
			// scoped inside that data member. Just consume it; the name is already captured.
			continue;
		case 'S': //<substitution>
			newType = DemangleSubstitution();
			substitute = false;
			break;
		case 'T': //<template-param>
			newType = DemangleTemplateSubstitution();
			break;
		case 'I': //<template-prefix> <template-args>
		{
			if (!base)
				throw DemangleException();
			ParamList args;
			bool hadNonType = false;
			DemangleTemplateArgs(args, allTypeTemplateArgs ? &hadNonType : nullptr);
			if (allTypeTemplateArgs)
				*allTypeTemplateArgs = !hadNonType;
			// Resolve any forward template refs created while parsing a cv
			// conversion operator type (e.g. cv T_ where T_ wasn't yet known).
			// Only do this in the outer context (not while still inside the cv
			// type parsing itself where m_permitForwardTemplateRefs is true).
			if (!m_permitForwardTemplateRefs)
				ResolveForwardTemplateRefs(type, args);
			ApplyTemplateArgs(type, std::move(args));
			isTemplate = true;
			break;
		}
		default:  //<unqualified-name> || <decltype>
			m_reader.UnRead(1);
			newType = DemangleUnqualifiedName();
			break;
		}

		base = true;
		if (!isTemplate)
		{
			type.SetNameType(newType.GetNameType());
			AppendTypeName(type, newType);
			type.SetNTRType(newType.GetNTRClass());
		}
		// Consume any ABI tags (B <source-name>) following this name component.
		// These appear as suffixes on <unqualified-name> in the Itanium ABI:
		//   <abi-tags> ::= <abi-tag> [<abi-tags>]
		//   <abi-tag>  ::= B <source-name>
		// We append them as "[abi:tag]" to the last name segment for display.
		// Save/restore m_lastName so that a following C1/D1 ctor/dtor name
		// still resolves to the class name, not the ABI tag string.
		while (m_reader.Peek() == 'B')
		{
			m_reader.Consume();
			string savedLastName = m_lastName;
			string abiTag = DemangleSourceName();
			m_lastName = savedLastName;
			ExtendTypeName(type, "[abi:" + abiTag + "]");
		}
		bool dependentTemplatePrefix = !pushBareTemplatePrefix && m_reader.Peek() == 'I' &&
			LastTypeNameSegmentBase(type) == "basic_ostream" &&
			TemplateArgsReferenceTemplateParam(m_reader.PeekString(m_reader.Length()));
		if (substitute && m_reader.Peek() != 'E' && !dependentTemplatePrefix)
		{
			//Those template arguments were not the primary arguments so clear them from the sub listType
			while (m_templateSubstitute.size() > startSize)
			{
				m_templateSubstitute.pop_back();
			}
			PushType(type);
		}
		MyLogDebug("%s:: '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	}
	m_reader.Consume();

	if (cnst || vltl || rstrct)
	{
		type.SetConst(cnst);
		type.SetVolatile(vltl);
		if (rstrct)
			type.AddPointerSuffix(RestrictSuffix);
	}

	if (ref)
	{
		type.AddPointerSuffix(rvalueRef?LvalueSuffix:ReferenceSuffix);
		PushType(type);
	}
	dedent();
	return type;
}


DemangledTypeNode DemangleGNU3::DemangleLocalName()
{
	NestingGuard nestingGuard(*this);
	indent();
	MyLogDebug("%s '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	DemangledTypeNode type;
	StringList varName;
	// The local function has its own template scope. Save the outer template
	// substitution table and set m_topLevel = true so that when the local
	// function's template args are parsed (e.g. handleMessageDelayed<T, T0, T1>),
	// they populate m_templateSubstitute and are available for T_/T0_/T1_
	// references in the function's parameter types.
	auto savedTemplateSubstitute = m_templateSubstitute;
	m_templateSubstitute.clear();
	bool oldTopLevel = m_topLevel;
	m_topLevel = true;
	bool savedInLocalName = m_inLocalName;
	m_inLocalName = true;
	type = DemangleSymbol(varName);
	m_inLocalName = savedInLocalName;

	if (varName.size() > 0)
		varName.back() += type.GetStringAfterName(m_platform.GetPtr());
	else
		varName.push_back(type.GetString());

	if (m_reader.Peek() != 's')
	{
		// Handle default argument context: d [<number>] _ <name>
		if (m_reader.Peek() == 'd')
		{
			m_reader.Consume();
			if (isdigit(m_reader.Peek()))
				DemangleNumber();
			if (m_reader.Peek() == '_')
				m_reader.Consume();
		}
		//<entity name>
		DemangledTypeNode tmpType = DemangleName();
		type = DemangledTypeNode::NamedType(UnknownNamedTypeClass, varName);
		AppendTypeName(type, tmpType);
		type.SetNTRType(tmpType.GetNTRClass());
		type.SetConst(tmpType.IsConst());
		type.SetVolatile(tmpType.IsVolatile());
		type.SetPointerSuffixBits(tmpType.GetPointerSuffixBits());
		m_templateSubstitute = std::move(savedTemplateSubstitute);
		m_topLevel = oldTopLevel;
	}
	else
	{
		m_reader.Consume();
		type = DemangledTypeNode::NamedType(UnknownNamedTypeClass, varName);
		m_templateSubstitute = std::move(savedTemplateSubstitute);
		m_topLevel = oldTopLevel;
	}
	// [<discriminator>]
	//TODO: What do we do with discriminators?
	if (m_reader.Peek() == '_')
	{
		m_reader.Consume();
		if (m_reader.Peek() == '_')
		{
			m_reader.Consume();
			DemangleNumberAsString();
			if (m_reader.Read() != '_')
				throw DemangleException();
		}
		else
		{
			DemangleNumberAsString();
		}
	}
	dedent();
	return type;
}


DemangledTypeNode DemangleGNU3::DemangleName()
{
	NestingGuard nestingGuard(*this);
	indent();
	MyLogDebug("%s '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	/*
	<name> ::= <nested-name>
	       ::= <unscoped-name>
	       ::= <unscoped-template-name> <template-args>
	       ::= <local-name>	# See Scope Encoding below

	<unscoped-name> ::= <unqualified-name>
	                ::= St <unqualified-name>   # ::std::

	<unscoped-template-name> ::= <unscoped-name>
	                         ::= <substitution>
	*/
	DemangledTypeNode type;
	bool substitute = false;
	switch (m_reader.Read())
	{
	case 'S':
		if (m_reader.Peek() == 't')
		{
			m_reader.Consume(1);
			type = DemangleUnqualifiedName();
			auto qn = CopyQualifiedName(type);
			qn.insert(qn.begin(), DemangledNamePart("std"));
			type.SetName(std::move(qn));
			substitute = true;
		}
		else
		{
			type = DemangleSubstitution();
		}

		if (m_reader.Peek() == 'I')
		{
			m_reader.Consume();
			if (substitute)
				PushType(type);
			ParamList args;
			DemangleTemplateArgs(args);
			ApplyTemplateArgs(type, std::move(args));
			// Push the template instantiation (e.g. std::swap<T>) so that the
			// substitution table matches what the encoder built.  The encoder adds
			// both the unscoped-template-name (prefix, already pushed above) and
			// the full template-id (instantiation).
			PushType(type);
		}
		break;
	case 'N': //<nested-name>
	{
		bool allTypeArgs = false;
		type = DemangleNestedName(&allTypeArgs);
		if (!m_inLocalName && allTypeArgs)
			PushType(type);
		break;
	}
	case 'Z': //<local-name>
		type = DemangleLocalName();
		break;
	default: //<unscoped-name> | <substitution>
		/*
		<unscoped-name> ::= <unqualified-name>
		                ::= St <unqualified-name>   # ::std::
		<unscoped-template-name> ::= <unscoped-name>
		                         ::= <substitution>
		*/
		m_reader.UnRead();
		if (m_reader.Peek() == 'L')
			m_reader.Consume();
		type = DemangleUnqualifiedName();
		if (m_reader.Peek() == 'I')
		{
			PushType(type);
			//<unscoped-template-name>
			ParamList args;
			m_reader.Consume();
			//<tmplate-args>
			DemangleTemplateArgs(args);
			ApplyTemplateArgs(type, std::move(args));
		}
	}
	dedent();
	return type;
}


DemangledTypeNode DemangleGNU3::DemangleSymbol(StringList& varName)
{
	NestingGuard nestingGuard(*this);
	indent();
	MyLogDebug("%s: %s\n", __FUNCTION__, m_reader.GetRaw().c_str());
	DemangledTypeNode returnType;
	NodeRef returnTypeRef = nullptr;
	bool isReturnTypeUnknown = false;
	DemangledTypeNode type;
	ParamList params;
	bool cnst = false, vltl = false, rstrct = false;
	bool oldTopLevel;
	StringList name;

	/*
	<encoding> ::= <function name> <bare-function-type>
	           ::= <data name>
	           ::= <special-name>
	*/
	//<special-name>
	switch (m_reader.Peek())
	{
	case 'G':
		m_reader.Consume();
		switch (m_reader.Read())
		{
		case 'A': //TODO hidden alias
			LogWarn("Unsupported demangle type: hidden alias\n");
			throw DemangleException();
		case 'R': // GR <object name> [<seq-id>] _  # reference temporary
		{
			// <object name> is a <name> production (nested, local, or unscoped).
			// For local names (Z prefix), DemangleLocalName consumes the trailing '_'
			// as a zero-discriminator, so we only consume '_' if it's still present.
			DemangledTypeNode nameNode = DemangleName();
			// Consume optional base-36 seq-id (digits + uppercase A-Z) before '_'.
			string seqId;
			while (m_reader.Length() > 0 && m_reader.Peek() != '_')
				seqId += m_reader.Read();
			if (m_reader.Length() > 0)
				m_reader.Consume(); // consume '_'
			string result = "reference_temporary_for_" + nameNode.GetString();
			if (!seqId.empty())
				result += "[" + seqId + "]";
			varName.push_back(result);
			return DemangledTypeNode::NamedType(UnknownNamedTypeClass, varName);
		}
		case 'T': // transaction clone: GTt<encoding> (safe) or GTn<encoding> (non-safe)
		{
			// consume the 't' (transaction-safe) or 'n' (non-transaction-safe) qualifier
			char kind = m_reader.Read();
			if (kind != 't' && kind != 'n')
				throw DemangleException();
			oldTopLevel = m_topLevel;
			m_topLevel = false;
			DemangledTypeNode t = DemangleSymbol(name);
			m_topLevel = oldTopLevel;
			return DemangledTypeNode::NamedType(UnknownNamedTypeClass,
				StringList{JoinNameSegments(name) + " [transaction clone]" + t.GetStringAfterName(m_platform.GetPtr())});
		}
		case 'V':
		{
			// Disambiguate: Intel Vector Function ABI (_ZGV<isa>...) vs guard variable (_ZGV<symbol>).
			// Intel Vector ABI isa codes: b c d e x y Y z Z
			// Guard variable encoding starts with: N (nested), L (local), S (substitution), digit, etc.
			char peekChar = m_reader.Peek();
			bool isVectorABI = (peekChar == 'b' || peekChar == 'c' || peekChar == 'd' || peekChar == 'e' ||
			                    peekChar == 'x' || peekChar == 'y' || peekChar == 'Y');
			// 'z'/'Z' are ambiguous: also used as Z-local-name prefix in guard variables
			// (e.g. _ZGVZN1A1BEvE1A = guard variable for A::B()::A).
			// Disambiguate by verifying the full Vector ABI parameter pattern:
			// <isa><mask(M|N)><vlen(digits)><vparams><'_'>  where vparams are only
			// from {v, l, u, R, L, s, 0-9} and are immediately followed by '_'.
			// A guard variable's inner symbol would have source-name chars (e.g. 'm', 'a', etc.)
			// that don't appear in valid vparameter sequences.
			if (!isVectorABI && (peekChar == 'z' || peekChar == 'Z'))
			{
				_STD_STRING ahead = m_reader.PeekString(std::min((size_t)32, m_reader.Length()));
				if (ahead.size() >= 3 && (ahead[1] == 'M' || ahead[1] == 'N'))
				{
					size_t pos = 2;
					while (pos < ahead.size() && isdigit((unsigned char)ahead[pos]))
						pos++;
					if (pos > 2) // had at least one vlen digit
					{
						// Scan through vparameter chars; valid ones are v/l/u/R/L and
						// optional stride digits/'s'. Anything else means guard variable.
						bool allVparam = true;
						while (pos < ahead.size() && ahead[pos] != '_')
						{
							char c = ahead[pos];
							if (c == 'v' || c == 'l' || c == 'u' || c == 'R' ||
							    c == 'L' || c == 's' || isdigit((unsigned char)c))
								pos++;
							else
							{
								allVparam = false;
								break;
							}
						}
						isVectorABI = allVparam && pos < ahead.size() && ahead[pos] == '_';
					}
				}
			}
			if (!isVectorABI)
			{
				// Guard variable (original behavior)
				DemangledTypeNode t = DemangleSymbol(name);
				varName.push_back("guard_variable_for_" + t.GetTypeAndName(name, m_platform.GetPtr()));
				type = DemangledTypeNode::IntegerType(1, false);
				if (m_reader.Length() == 0)
					return type;
				//function parameters
				string paramList;
				paramList += "(";
				bool first = true;
				do
				{
					if (m_reader.Peek() == 'v')
					{
						m_reader.Consume();
						break;
					}
					if (!first)
						paramList += ", ";
					paramList += DemangleTypeString();
				}while (m_reader.Peek() != 'E');
				m_reader.Consume();
				varName.back() += paramList + ")";
				varName.push_back(DemangleSourceName());

				return type;
			}



			// Intel Vector Function ABI:
			// GV <isa> <mask> <vlen> <vparameters> '_' <routine_name>

			// Parse ISA
			char isa = m_reader.Read();
			const char* isaName;
			switch (isa)
			{
			case 'b': isaName = "SSE2"; break;
			case 'c': isaName = "SSE4.2"; break;
			case 'd': isaName = "AVX"; break;
			case 'e': isaName = "AVX512"; break;
			case 'x': isaName = "SSE2"; break;
			case 'y': isaName = "AVX"; break;
			case 'Y': isaName = "AVX2"; break;
			case 'z': isaName = "MIC"; break;
			case 'Z': isaName = "AVX512"; break;
			default:  isaName = "unknown"; break;
			}

			// Parse mask: 'M' (mask) or 'N' (nomask)
			char maskChar = m_reader.Read();
			if (maskChar != 'M' && maskChar != 'N')
				throw DemangleException();
			const char* maskName = (maskChar == 'M') ? "mask" : "nomask";

			// Parse vlen: non-negative decimal integer
			if (!isdigit(m_reader.Peek()))
				throw DemangleException();
			string vlenStr;
			while (isdigit(m_reader.Peek()))
				vlenStr += m_reader.Read();

			// Parse vparameters until '_' separator
			// <vparameter> <opt-align>
			// <vparameter> ::= ('l'|'R'|'U'|'L') <stride>  |  'u'  |  'v'
			// <stride>     ::= empty | 's' <decimal> | <number>
			// <opt-align>  ::= empty | 'a' <decimal>
			string paramsStr;
			bool firstParam = true;
			while (m_reader.Length() > 0 && m_reader.Peek() != '_')
			{
				if (!firstParam)
					paramsStr += ',';
				firstParam = false;

				char pc = m_reader.Read();
				bool hasStride = false;
				switch (pc)
				{
				case 'l': paramsStr += "linear"; hasStride = true; break;
				case 'R': paramsStr += "linear(ref)"; hasStride = true; break;
				case 'U': paramsStr += "linear(uval)"; hasStride = true; break;
				case 'L': paramsStr += "linear(val)"; hasStride = true; break;
				case 'u': paramsStr += "uniform"; break;
				case 'v': paramsStr += "vector"; break;
				default:  throw DemangleException();
				}

				if (hasStride)
				{
					if (m_reader.Peek() == 's')
					{
						// linear_step passed as another argument at given 0-based position
						m_reader.Consume();
						string argPos;
						while (isdigit(m_reader.Peek()))
							argPos += m_reader.Read();
						paramsStr += "(step=arg" + argPos + ")";
					}
					else if (isdigit(m_reader.Peek()) || m_reader.Peek() == 'n')
					{
						// Literal stride; 'n' prefix means negative
						string stride = DemangleNumberAsString();
						paramsStr += "(step=" + stride + ")";
					}
					// else: empty stride means step of 1
				}

				// Optional alignment: 'a' <non-negative-decimal>
				if (m_reader.Peek() == 'a')
				{
					m_reader.Consume();
					while (isdigit(m_reader.Peek()))
						m_reader.Read();
				}
			}

			// Consume the '_' separator between parameters and routine name
			if (m_reader.Length() == 0 || m_reader.Read() != '_')
				throw DemangleException();

			// Remainder is the scalar routine name (may be a plain C name or a _Z mangled name)
			string routineName = m_reader.ReadString(m_reader.Length());

			// Build the human-readable annotation
			string annotation = " [SIMD:";
			annotation += isaName;
			annotation += ',';
			annotation += maskName;
			annotation += ",N=";
			annotation += vlenStr;
			if (!paramsStr.empty())
			{
				annotation += ",(";
				annotation += paramsStr;
				annotation += ')';
			}
			annotation += ']';

			return DemangledTypeNode::NamedType(UnknownNamedTypeClass,
				StringList{routineName + annotation});
		}
		default:
			throw DemangleException();
		}
	case 'T':
		/*
		<special-name> ::= TV <type>	# virtual table
		               ::= TT <type>	# VTT structure (construction vtable index)
		               ::= TI <type>	# typeinfo structure
		               ::= TS <type>	# typeinfo name (null-terminated byte string)
		               ::= T <call-offset> <base encoding>
		                   # base is the nominal target function of thunk
		<call-offset>  ::= h <nv-offset> _
		               ::= v <v-offset> _
		<nv-offset>    ::= <offset number> # non-virtual base override
		<v-offset>     ::= <offset number> _ <virtual offset number>
		                   # virtual base override, with vcall offset
		*/
		m_reader.Consume();
		switch (m_reader.Read())
		{
		case 'c': // covariant return thunk: Tc <call-offset> <call-offset> <encoding>
		{
			// consume a call-offset: h <number> _  or  v <number> _ <number> _
			auto consumeCallOffset = [&]() {
				char kind = m_reader.Read();
				if (kind == 'h')
				{
					DemangleNumberAsString();
					if (m_reader.Read() != '_')
						throw DemangleException();
				}
				else if (kind == 'v')
				{
					DemangleNumberAsString();
					if (m_reader.Read() != '_')
						throw DemangleException();
					DemangleNumberAsString();
					if (m_reader.Read() != '_')
						throw DemangleException();
				}
				else
					throw DemangleException();
			};
			consumeCallOffset(); // this-pointer adjustment
			consumeCallOffset(); // return-value adjustment
			oldTopLevel = m_topLevel;
			m_topLevel = false;
			DemangledTypeNode t = DemangleSymbol(name);
			m_topLevel = oldTopLevel;
			return DemangledTypeNode::NamedType(UnknownNamedTypeClass,
				StringList{"covariant_return_thunk_to_" + JoinNameSegments(name) + t.GetStringAfterName(m_platform.GetPtr())});
		}
		case 'C':
		{
			DemangledTypeNode t = DemangleType();
			DemangleNumberAsString();
			if (m_reader.Read() != '_')
				throw DemangleException();

			return DemangledTypeNode::NamedType(UnknownNamedTypeClass,
				StringList{"construction_vtable_for_" + DemangleTypeString() + "-in-" + t.GetString()});
		}
		case 'D':
			LogWarn("Unsupported: 'typeinfo common proxy'\n");
			throw DemangleException();
		case 'F':
			LogWarn("Unsupported: 'typeinfo fn'\n");
			throw DemangleException();
		case 'h': //TODO: Convert to whatever the actual type is!
		{
			DemangleNumberAsString();
			if (m_reader.Read() != '_')
				throw DemangleException();
			oldTopLevel = m_topLevel;
			m_topLevel = false;
			DemangledTypeNode t = DemangleSymbol(name);
			m_topLevel = oldTopLevel;
			return DemangledTypeNode::NamedType(UnknownNamedTypeClass,
				StringList{"non-virtual_thunk_to_" + JoinNameSegments(name) + t.GetStringAfterName(m_platform.GetPtr())});
		}
		case 'H': // TLS init function
		{
			oldTopLevel = m_topLevel;
			m_topLevel = false;
			DemangledTypeNode t = DemangleSymbol(name);
			m_topLevel = oldTopLevel;
			return DemangledTypeNode::NamedType(UnknownNamedTypeClass,
				StringList{"tls_init_function_for_" + t.GetTypeAndName(name, m_platform.GetPtr())});
		}
		case 'I':
			return DemangledTypeNode::NamedType(UnknownNamedTypeClass,
				StringList{"typeinfo_for_" + DemangleTypeString()});
		case 'J':
			LogWarn("Unsupported: 'java class'\n");
			throw DemangleException();
		case 'S':
		{
			DemangledTypeNode t = DemangleType();
			varName = vector<string>{"typeinfo_name_for_" + t.GetString()};
			DemangledTypeNode elemType = DemangledTypeNode::IntegerType(1, true);
			return DemangledTypeNode::ArrayType(std::move(elemType), 0);
		}
		case 'T': //VTT
		{
			DemangledTypeNode t = DemangleType();
			return DemangledTypeNode::NamedType(StructNamedTypeClass,
				StringList{"VTT_for_" + t.GetString()});
		}
		case 'v': // virtual thunk
		{
			DemangleNumberAsString();
			if (m_reader.Read() != '_')
				throw DemangleException();
			DemangleNumberAsString();
			if (m_reader.Read() != '_')
				throw DemangleException();
			oldTopLevel = m_topLevel;
			m_topLevel = false;
			DemangledTypeNode t = DemangleSymbol(name);
			m_topLevel = oldTopLevel;
			return DemangledTypeNode::NamedType(UnknownNamedTypeClass,
				StringList{"virtual_thunk_to_" + JoinNameSegments(name) + t.GetStringAfterName(m_platform.GetPtr())});
		}
		case 'V': //Vtable
			return DemangledTypeNode::NamedType(StructNamedTypeClass,
				StringList{"vtable_for_" + DemangleTypeString()});
		case 'W': // TLS wrapper function
		{
			oldTopLevel = m_topLevel;
			m_topLevel = false;
			DemangledTypeNode t = DemangleSymbol(name);
			m_topLevel = oldTopLevel;
			return DemangledTypeNode::NamedType(UnknownNamedTypeClass,
				StringList{"tls_wrapper_function_for_" + t.GetTypeAndName(name, m_platform.GetPtr())});
		}
		default:
			throw DemangleException();
		}
	default: break;
	}

	//<function name> or <data name>
	type = DemangleName();
	if (m_reader.Length() == 0)
	{
		return type;
	}

	if (m_reader.Peek() == 'E')
	{
		m_reader.Consume();
		return type;
	}

	cnst = type.IsConst();
	vltl = type.IsVolatile();
	auto suffix = type.GetPointerSuffixBits();
	if (m_reader.Peek() == 'J')
	{
		m_reader.Consume();
		// TODO: If we get here we have a return type. What can we do with this info?
	}
	// Consume any ABI tags on the function/data name (e.g. B5cxx11).
	// For nested names these are already consumed inside DemangleNestedName();
	// this handles the global-scope case.
	while (m_reader.Peek() == 'B')
	{
		m_reader.Consume();
		string savedLastName = m_lastName;
		string abiTag = DemangleSourceName();
		m_lastName = savedLastName;
		ExtendTypeName(type, "[abi:" + abiTag + "]");
	}
	const bool nameRequiresReturnType = m_isParameter || LastTypeNameSegmentHasTemplateArguments(type);
	varName = type.RenderTypeNameSegments(m_platform.GetPtr());
	if (m_isOperatorOverload ||
		type.GetNameType() == ConstructorNameType ||
		type.GetNameType() == DestructorNameType)
	{
		returnType = DemangledTypeNode::VoidType();
	}
	else if (nameRequiresReturnType)
	{
		returnType = DemangleType();
		returnTypeRef = m_lastTypeRef;
	}
	else
	{
		isReturnTypeUnknown = true;
		returnType = DemangledTypeNode::AddressSizedIntegerType(true);
	}

	m_functionSubstitute.push_back({});
	while (m_reader.Length() > 0)
	{
		if (m_reader.Peek() == 'E')
		{
			m_reader.Consume();
			break;
		}
		if (m_reader.Peek() == '.')
		{
			// Extension, consume the rest
			string ext = m_reader.ReadString(m_reader.Length());

			if (ext == ".eh") ext = "exception handler";
			else if (ext == ".eh_frame") ext = "exception handler frame";
			else if (ext == ".eh_frame_hdr") ext = "exception handler frame header";
			else if (ext == ".debug_frame") ext = "debug frame";

			// On the off chance some invalid mangled string is passed in.
			if (varName.size() > 0)
				varName.back() += " " + ext;
			break;
		}

		m_isParameter = true;
		MyLogDebug("Var: %s\n", m_reader.GetRaw().c_str());
		if (m_reader.PeekString(2) == "@@")
			break;
		DemangledTypeNode param = DemangleType();
		NodeRef paramRef = m_lastTypeRef;
		if (param.GetClass() == VoidTypeClass)
		{
			if (m_reader.Peek() == 'E')
			{
				m_reader.Consume();
				break;
			}
			break;
		}
		bool isVarArgs = param.GetClass() == VarArgsTypeClass;
		if (!paramRef)
			paramRef = DemangledTypeNode::CreateShared(std::move(param));
		m_functionSubstitute.back().push_back(paramRef);
		params.push_back({"", paramRef});
		if (isVarArgs)
		{
			if (m_reader.Peek() == 'E')
			{
				m_reader.Consume();
			}

			break;
		}
	}

	m_functionSubstitute.pop_back();
	m_isParameter = false;
	if (!returnTypeRef)
		returnTypeRef = DemangledTypeNode::CreateShared(std::move(returnType));
	type = DemangledTypeNode::FunctionType(returnTypeRef, nullptr, std::move(params));
	if (isReturnTypeUnknown)
		type.SetReturnTypeConfidence(BN_MINIMUM_CONFIDENCE);

	type.SetPointerSuffixBits(suffix);
	type.SetConst(cnst);
	type.SetVolatile(vltl);
	if (rstrct)
		type.SetPointerSuffixBits(1u << RestrictSuffix);

	// PrintTables();
	MyLogDebug("Done: %s%s%s\n", type.GetStringBeforeName(m_platform.GetPtr()).c_str(), JoinNameSegments(varName).c_str(),
		type.GetStringAfterName(m_platform.GetPtr()).c_str());

	dedent();
	return type;
}


// ===== Non-templated static methods =====

bool DemangleGNU3Static::IsGNU3MangledString(const string& name)
{
	string headerless = name;
	string header;
	if (DemangleGlobalHeader(headerless, header))
		return true;

	if (!headerless.compare(0, 2, "_Z") || !headerless.compare(0, 3, "__Z"))
		return true;

	return false;
}


bool DemangleGNU3Static::DemangleGlobalHeader(string& name, string& header)
{
	size_t strippedCount = 0;
	string encoded = name;
	while (encoded[0] == '_')
	{
		encoded.erase(0, 1);
		strippedCount ++;
	}

	if (strippedCount == 0)
		return false;

	static const vector<pair<string, string>> headers = {
		{"GLOBAL__sub_I_", "(static initializer)"},
		{"GLOBAL__I_", "(global initializer)"},
		{"GLOBAL__D_", "(global destructor)"},
	};

	for (auto& i: headers)
	{
		if (encoded.size() > i.first.size() && encoded.substr(0, i.first.size()) == i.first)
		{
			name = name.substr(i.first.size() + strippedCount);
			header = i.second;
			return true;
		}
	}

	return false;
}


namespace
{
	static bool DemangleStringGNU3Segments(
		Platform* platform, const string& name, Ref<Type>& outType, StringList& outVarName)
	{
		// Handle _block_invoke[.N] and _block_invoke_N suffixes (Clang/Apple block invocations).
		// E.g. ____ZN4dyld5_mainEPK12macho_headermiPPKcS5_S5_Pm_block_invoke.110
		//   -> "invocation_function_for_block_in_dyld::_main(...)"
		static const string blockInvokeSuffix = "_block_invoke";
		size_t blockPos = name.rfind(blockInvokeSuffix);
		if (blockPos != string::npos)
		{
			// Verify the suffix is _block_invoke optionally followed by [._]<digits> only
			string tail = name.substr(blockPos + blockInvokeSuffix.size());
			bool validSuffix = tail.empty();
			if (!validSuffix && (tail[0] == '.' || tail[0] == '_'))
			{
				size_t i = 1;
				while (i < tail.size() && isdigit((unsigned char)tail[i]))
					i++;
				validSuffix = (i == tail.size() && i > 1);
			}
			if (validSuffix)
			{
				// Extract the base symbol: everything before _block_invoke
				string base = name.substr(0, blockPos);
				// Normalize leading underscores: find 'Z' after underscores, keep one '_' before it
				size_t zPos = base.find_first_not_of('_');
				if (zPos != string::npos && base[zPos] == 'Z')
				{
					string normalized = "_" + base.substr(zPos);
					Ref<Type> baseType;
					StringList baseName;
					if (DemangleStringGNU3Segments(platform, normalized, baseType, baseName))
					{
						outVarName.clear();
						outVarName.push_back("invocation_function_for_block_in_" + JoinNameSegments(baseName));
						outType = baseType;
						return true;
					}
				}
			}
		}

		// Handle macOS thread-local variable initializer suffix: $tlv$init
		// E.g. __ZL9recursive$tlv$init -> demangle "__ZL9recursive" then annotate.
		static const string tlvInitSuffix = "$tlv$init";
		if (name.size() > tlvInitSuffix.size() &&
			name.compare(name.size() - tlvInitSuffix.size(), tlvInitSuffix.size(), tlvInitSuffix) == 0)
		{
			string base = name.substr(0, name.size() - tlvInitSuffix.size());
			Ref<Type> baseType;
			StringList baseName;
			if (DemangleStringGNU3Segments(platform, base, baseType, baseName))
			{
				outVarName = std::move(baseName);
				if (outVarName.size() > 0)
					outVarName[outVarName.size() - 1] += "$tlv$init";
				else
					outVarName.push_back("$tlv$init");
				outType = baseType;
				return true;
			}
		}

		string encoding = name;
		string header;
		bool foundHeader = DemangleGNU3Static::DemangleGlobalHeader(encoding, header);

		if (!encoding.compare(0, 2, "_Z"))
			encoding = encoding.substr(2);
		else if (!encoding.compare(0, 3, "__Z"))
			encoding = encoding.substr(3);
		else if (foundHeader && !header.empty())
		{
			outVarName.clear();
			outVarName.push_back(header);
			outVarName.push_back(encoding);
			outType = DemangledTypeNode::NamedType(UnknownNamedTypeClass, outVarName).Finalize(platform);
			return true;
		}
		else
			return false;

		thread_local DemangleGNU3 demangle(platform, encoding);
		demangle.Reset(platform, encoding);
		try
		{
			outType = demangle.DemangleSymbol(outVarName).Finalize(platform);

			if (outVarName.size() == 0)
			{
				if (GetFinalizedTypeClass(outType) == NamedTypeReferenceClass &&
					outType->GetNamedTypeReference()->GetTypeReferenceClass() == UnknownNamedTypeClass)
				{
					const auto typeName = outType->GetTypeName();
					outVarName = StringList(typeName.begin(), typeName.end());
					outType = nullptr;
				}
				else if (GetFinalizedTypeClass(outType) == NamedTypeReferenceClass)
				{
					auto typeName = outType->GetTypeName();
					if (typeName.size() > 0)
						outVarName = StringList{"_" + typeName[typeName.size() - 1]};
				}
			}

			if (foundHeader && !header.empty())
				outVarName.insert(outVarName.begin(), header);
		}
		catch (const DemangleException&)
		{
			return false;
		}
		return true;
	}
}


bool DemangleGNU3Static::DemangleStringGNU3(Platform* platform, const string& name, Ref<Type>& outType,
	QualifiedName& outVarName)
{
	StringList outVarNameSegments;
	if (!DemangleStringGNU3Segments(platform, name, outType, outVarNameSegments))
		return false;
	outVarName = QualifiedName(outVarNameSegments);
	return true;
}


bool DemangleGNU3Static::DemangleStringGNU3(Architecture* arch, const string& name, Ref<Type>& outType,
	QualifiedName& outVarName)
{
	Ref<Platform> platform;
	if (arch)
		platform = arch->GetStandalonePlatform();
	return DemangleStringGNU3(platform.GetPtr(), name, outType, outVarName);
}


// ===== Explicit template instantiation =====


// ===== Demangler plugin registration =====

class GNU3Demangler: public Demangler
{
public:
	GNU3Demangler(): Demangler("GNU3")
	{
	}
	~GNU3Demangler() override {}

	virtual bool IsMangledString(const string& name) override
	{
		return DemangleGNU3Static::IsGNU3MangledString(name);
	}

#ifdef BINARYNINJACORE_LIBRARY
	virtual bool Demangle(Architecture* arch, const string& name, Ref<Type>& outType, QualifiedName& outVarName,
	                      BinaryView* view) override
#else
	virtual bool Demangle(Ref<Architecture> arch, const string& name, Ref<Type>& outType, QualifiedName& outVarName,
	                      Ref<BinaryView> view) override
#endif
	{
		if (view)
		{
			auto platform = view->GetDefaultPlatform();
			if (platform)
#ifdef BINARYNINJACORE_LIBRARY
				return DemangleGNU3Static::DemangleStringGNU3(platform, name, outType, outVarName);
#else
				return DemangleGNU3Static::DemangleStringGNU3(platform.GetPtr(), name, outType, outVarName);
#endif
		}
		return DemangleGNU3Static::DemangleStringGNU3(arch, name, outType, outVarName);
	}
};


extern "C"
{
#ifndef BINARYNINJACORE_LIBRARY
	BN_DECLARE_CORE_ABI_VERSION
#endif

#ifdef BINARYNINJACORE_LIBRARY
	bool DemangleGNU3PluginInit()
#elif defined(DEMO_EDITION)
	bool DemangleGNU3PluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		static GNU3Demangler* demangler = new GNU3Demangler();
		Demangler::Register(demangler);
		return true;
	}
}
