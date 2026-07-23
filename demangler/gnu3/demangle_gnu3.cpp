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
#include "demangler/demangled_log.h"
#include "demangler/demangled_template_simplifier.h"
#include <cstdarg>
#include <algorithm>
#include <memory>


#ifdef BINARYNINJACORE_LIBRARY
using namespace BinaryNinjaCore;
#else
using namespace BinaryNinja;
using namespace std;
#endif

namespace
{
	BNTypeClass GetFinalizedTypeClass(const Ref<Type>& type)
	{
#ifdef BINARYNINJACORE_LIBRARY
		return type->GetTypeClass();
#else
		return type->GetClass();
#endif
	}

#define hash(x,y) (64 * (x) + (y))

#ifdef GNUDEMANGLE_DEBUG
	void LogWithIndentation(const char* fmt, ...)
	{
		va_list args;
		va_start(args, fmt);
		_STD_STRING indentedFormat = DemangleLogIndentation::Apply(fmt);
		PerformLog(0, DebugLog, "", 0, indentedFormat.c_str(), args);
		va_end(args);
	}

#define LOG_INDENTATION_SCOPE DemangleLogIndentationScope logIndentationScope
#else
#define LogWithIndentation(...) do {} while(0)
#define LOG_INDENTATION_SCOPE do {} while(0)
#endif

	size_t TotalStringSize(const StringList& v)
	{
		size_t n = 0;
		for (const auto& s : v)
			n += s.size();
		return n;
	}


	string JoinNameSegments(const StringList& name)
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


	bool TemplateArgsReferenceTemplateParam(std::string_view raw)
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


	DemangledNamePart NameSegmentWithTemplateArgs(std::string_view name, vector<DemangledTypeNode::Param> args)
	{
		return {string(name), std::move(args), true};
	}


	void AppendStructuredNameSegments(DemangledQualifiedName& name, const StringList& segments)
	{
		for (const auto& segment: segments)
			name.emplace_back(segment);
	}


	void SetStructuredExpressionNode(DemangledTypeNode* outNode, const DemangledQualifiedName& name)
	{
		if (outNode && !name.empty())
		{
			if (name.size() > 1 && !name.back().HasTemplateArguments())
			{
				DemangledQualifiedName baseName(name.begin(), name.end() - 1);
				DemangledTypeNode baseType = DemangledTypeNode::NamedType(std::move(baseName));
				*outNode = DemangledTypeNode::PostfixType(
					DemangledTypeNode::CreateShared(std::move(baseType)), "::" + name.back().GetString());
				return;
			}
			*outNode = DemangledTypeNode::NamedType(name);
		}
	}


	std::string_view GetOperator(char elm1, char elm2)
	{
		switch (hash(elm1, elm2))
		{
			case hash('d','c'): return "dynamic_cast";
			case hash('s','c'): return "static_cast";
			case hash('c','c'): return "const_cast";
			case hash('r','c'): return "reinterpret_cast";
			case hash('t','i'): [[fallthrough]];
			case hash('t','e'): return "typeid";
			case hash('s','t'): [[fallthrough]];
			case hash('s','z'): return "sizeof";
			case hash('a','t'): [[fallthrough]];
			case hash('a','z'): return "alignof";
			case hash('a','w'): return "co_await";
			case hash('n','x'): return "noexcept";
			case hash('s','Z'): [[fallthrough]];
			case hash('s','P'): return "sizeof...";
			case hash('s','p'): return "";
			case hash('t','w'): [[fallthrough]];
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
			case hash('n','g'): [[fallthrough]]; // - (unary)
			case hash('m','i'): return "-";   // -
			case hash('p','s'): [[fallthrough]]; // + (unary)
			case hash('p','l'): return "+";   // +
			case hash('a','d'): [[fallthrough]]; // & (unary)
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


	BNNameType GetNameType(char elm1, char elm2)
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
	string DecodeHexFloat(std::string_view hex, size_t byteCount)
	{
		if (hex.size() != byteCount * 2)
			return string(hex);

		// Parse big-endian hex into an integer, then reinterpret as float/double
		uint64_t bits = 0;
		for (size_t i = 0; i < hex.size(); i++)
		{
			char c = hex[i];
			uint64_t nibble;
			if (c >= '0' && c <= '9')      nibble = c - '0';
			else if (c >= 'a' && c <= 'f') nibble = c - 'a' + 10;
			else if (c >= 'A' && c <= 'F') nibble = c - 'A' + 10;
			else return string(hex);
			bits = (bits << 4) | nibble;
		}

		if (byteCount == 4)
		{
			union { uint32_t i; float f; } u;
			u.i = static_cast<uint32_t>(bits);
			if (std::isnan(u.f) || std::isinf(u.f))
			{
				string out = "(float)";
				out.append(hex);
				return out;
			}
			return to_string(u.f);
		}
		else if (byteCount == 8)
		{
			union { uint64_t i; double d; } u;
			u.i = bits;
			if (std::isnan(u.d) || std::isinf(u.d))
			{
				string out = "(double)";
				out.append(hex);
				return out;
			}
			return to_string(u.d);
		}
		return string(hex);
	}


	void ExtendTypeName(DemangledTypeNode& type, std::string_view extend)
	{
		if (type.GetClass() != NamedTypeReferenceClass)
			return;

		DemangledQualifiedName name = type.GetName();
		if (name.empty())
		{
			name.emplace_back(extend);
			type.SetName(std::move(name));
			return;
		}

		name.back().AppendBase(extend);
		type.SetName(std::move(name));
	}


	void ApplyTemplateArgs(DemangledTypeNode& type, DemangleGNU3::ParamList args)
	{
		if (type.GetClass() != NamedTypeReferenceClass)
			return;

		DemangledQualifiedName qn = type.GetName();
		if (qn.empty())
			qn.emplace_back("");

		qn.back().SetTemplateArguments(std::move(args), true);
		type.SetName(std::move(qn));
	}


	void AppendTypeName(DemangledTypeNode& type, const DemangledTypeNode& extend)
	{
		if (type.GetClass() != NamedTypeReferenceClass)
			return;

		DemangledQualifiedName newName = type.GetName();
		DemangledQualifiedName extendName = extend.GetName();
		newName.reserve(newName.size() + extendName.size());
		newName.insert(newName.end(), extendName.begin(), extendName.end());
		type.SetName(std::move(newName));
	}


	std::string_view LastTypeNameSegmentBase(const DemangledTypeNode& type)
	{
		const auto& qn = type.GetName();
		if (!qn.empty())
			return qn.back().GetBase();
		return {};
	}


	bool LastTypeNameSegmentHasTemplateArguments(const DemangledTypeNode& type)
	{
		const auto& qn = type.GetName();
		if (qn.empty())
			return false;
		return qn.back().HasTemplateArguments();
	}
}

// ===== DemangleGNU3 implementation =====

DemangleGNU3::DemangleGNU3(Platform& platform, string mangledName) :
	m_mangledName(std::move(mangledName)),
	m_reader(m_mangledName, MAX_DEMANGLE_NODE_LENGTH, false),
	m_platform(platform),
	m_lastTypeRef(nullptr),
	m_isParameter(false),
	m_topLevel(true),
	m_isOperatorOverload(false),
	m_parsingLambdaParams(false),
	m_lambdaTemplateParamBase(0),
	m_permitForwardTemplateRefs(false),
	m_inLocalName(false),
	m_nestingDepth(0)
{
	LogWithIndentation("%s : %s\n", __FUNCTION__, m_reader.GetRaw());
}

void DemangleGNU3::Reset(Platform& platform, string mangledName)
{
	m_mangledName = std::move(mangledName);
	m_reader.Reset(m_mangledName);
	m_platform = std::ref(platform);
	m_substitute.clear();
	m_templateSubstitute.clear();
	m_functionSubstitute.clear();
	m_lastTypeRef = nullptr;
	m_lastName.clear();
	m_isParameter = false;
	m_topLevel = true;
	m_isOperatorOverload = false;
	m_parsingLambdaParams = false;
	m_lambdaTemplateParamBase = 0;
	m_permitForwardTemplateRefs = false;
	m_pendingForwardRefs.clear();
	m_inLocalName = false;
	m_nestingDepth = 0;
}


void DemangleGNU3::PushEmptyTemplateParamSubstitution()
{
	m_templateSubstitute.emplace_back(NodeRef::TemplateParamPack({}));
}


#ifdef GNUDEMANGLE_DEBUG
const DemangledTypeNode& DemangleGNU3::GetTemplateType(size_t ref)
{
	if (ref >= m_templateSubstitute.size())
		throw DemangleException();
	if (m_templateSubstitute[ref].emptyTemplatePack || !m_templateSubstitute[ref])
		throw DemangleException();
	return *m_templateSubstitute[ref];
}
#endif


DemangleGNU3::NodeRef DemangleGNU3::PushType(const DemangledTypeNode& type)
{
	auto ref = DemangledTypeNode::CreateSharedCopy(type);
	m_substitute.emplace_back(ref);
	return ref;
}


DemangleGNU3::NodeRef DemangleGNU3::PushType(DemangledTypeNode&& type)
{
	auto ref = DemangledTypeNode::CreateShared(std::move(type));
	m_substitute.emplace_back(ref);
	return ref;
}


DemangleGNU3::NodeRef DemangleGNU3::GetTypeRef(size_t ref)
{
	if (ref >= m_substitute.size())
		throw DemangleException();
	if (m_substitute[ref].emptyTemplatePack || !m_substitute[ref])
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
		if (m_substitute[i].emptyTemplatePack)
			LogDebug("[%d] <empty template pack>\n", i - 1);
		else
			LogDebug("[%d] %s\n", i - 1, GetType(i).GetString().c_str());
	}

	LogDebug("Template Table\n");
	for (int i = 0; (size_t)i < m_templateSubstitute.size(); i++)
	{
		if (m_templateSubstitute[i].emptyTemplatePack)
			LogDebug("[%d] <empty template pack>\n", i - 1);
		else
			LogDebug("[%d] %s\n", i - 1, GetTemplateType(i).GetString().c_str());
	}
}
#endif


void DemangleGNU3::DemangleCVQualifiers(bool& cnst, bool& vltl, bool& rstrct)
{
	cnst = false; vltl = false; rstrct = false;
	//[<cv-qualifier>]
	while (true)
	{
		if (m_reader.ConsumeIf('r'))
			rstrct = true;
		else if (m_reader.ConsumeIf('V'))
			vltl = true;
		else if (m_reader.ConsumeIf('K'))
			cnst = true;
		else
			return;
	}
}


std::string_view DemangleGNU3::DemangleSourceName()
{
	LOG_INDENTATION_SCOPE;
	LogWithIndentation("%s : %s\n", __FUNCTION__, m_reader.GetRaw());
	std::string_view name = m_reader.ReadStringView(DemangleNumber());
	m_lastName = name;
	return name;
}


DemangledTypeNode DemangleGNU3::DemangleFunction(bool cnst, bool vltl)
{
	NestingGuard nestingGuard(m_nestingDepth);
	LOG_INDENTATION_SCOPE;
	LogWithIndentation("%s : %s\n", __FUNCTION__, m_reader.GetRaw());
	bool old_isparam;
	if (m_reader.ConsumeIf('Y'))
	{
		// TODO: This function is external, should we do anything with that info?
	}

	DemangledTypeNode retType = DemangleType();
	NodeRef retTypeRef = m_lastTypeRef;

	ParamList params;
	old_isparam = m_isParameter;
	m_isParameter = true;
	m_functionSubstitute.emplace_back();
	[[maybe_unused]] int i = 0;
	while (!m_reader.ConsumeIf('E'))
	{
		DemangledTypeNode param = DemangleType();
		NodeRef paramRef = m_lastTypeRef;
		if (AppendTemplateParamPackExpansion(params, paramRef, true))
			continue;
		if (param.GetClass() == VoidTypeClass)
			continue;
		LogWithIndentation("Var_%d - %s\n", i++, param.GetString().c_str());
		if (!paramRef)
			paramRef = DemangledTypeNode::CreateShared(std::move(param));
		m_functionSubstitute.back().emplace_back(paramRef);
		params.push_back({"", paramRef});
	}
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
	LogWithIndentation("After %s : %s\n", __FUNCTION__, m_reader.GetRaw());
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
		if (args[ref.index].type->ContainsNodeRef(ref.typeRef))
		{
			LogWarnF("Rejecting GNU3 demangle: recursive forward template reference T{}_", ref.index);
			throw DemangleException("Detected recursive forward template reference");
		}
		*ref.typeRef = *args[ref.index].type;
	}
	m_pendingForwardRefs.clear();
}


DemangleGNU3::NodeRef DemangleGNU3::DemangleTemplateSubstitutionEntry(NodeRef* outTypeRef)
{
	LOG_INDENTATION_SCOPE;
	LogWithIndentation("%s : %s\n", __FUNCTION__, m_reader.GetRaw());
	if (outTypeRef)
		*outTypeRef = nullptr;
	size_t number = 0;
	char elm = m_reader.PeekOr();
	if (elm == '_')
	{
		number = 0;
	}
	else if (isdigit(elm))
	{
		size_t n = 0;
		while (isdigit(m_reader.PeekOr()))
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

	if (!m_reader.ConsumeIf('_'))
	{
		throw DemangleException();
	}

	if (number < m_templateSubstitute.size())
	{
		const auto& entry = m_templateSubstitute[number];
		if (entry.emptyTemplatePack)
			return entry;
		if (!entry)
			throw DemangleException();
		if (outTypeRef)
			*outTypeRef = entry;
		return entry;
	}

	// If forward template references are permitted (e.g. inside a cv conversion
	// operator type), return a shared placeholder node whose contents will be
	// replaced once the outer template args are known.
	if (m_permitForwardTemplateRefs)
	{
		auto typeRef = DemangledTypeNode::CreateShared(DemangledTypeNode::NamedType("auto"));
		m_pendingForwardRefs.push_back({number, typeRef});
		if (outTypeRef)
			*outTypeRef = typeRef;
		return typeRef;
	}

	if (m_parsingLambdaParams && number >= m_lambdaTemplateParamBase)
	{
		auto typeRef = DemangledTypeNode::CreateShared(DemangledTypeNode::NamedType("auto"));
		if (outTypeRef)
			*outTypeRef = typeRef;
		return typeRef;
	}

	throw DemangleException();
}


DemangledTypeNode DemangleGNU3::DemangleTemplateSubstitution(NodeRef* outTypeRef)
{
	NodeRef entry = DemangleTemplateSubstitutionEntry(outTypeRef);
	if (entry.IsTemplateParamPack())
	{
		if (outTypeRef)
			*outTypeRef = entry;
		if (entry.emptyTemplatePack)
			return DemangledTypeNode::VoidType();
		return *entry;
	}
	if (entry.emptyTemplatePack || !entry)
		throw DemangleException();
	return *entry;
}


DemangledTypeNode DemangleGNU3::DemangleType()
{
	NestingGuard nestingGuard(m_nestingDepth);
	LOG_INDENTATION_SCOPE;
	LogWithIndentation("%s : %s\n", __FUNCTION__, m_reader.GetRaw());
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
		char next = m_reader.PeekOr();
		if (isdigit(next) || next == '_' || isupper(next))
		{
			type = DemangleSubstitution(&typeRef);
			if (m_reader.ConsumeIf('I'))
			{
				ParamList args;
				DemangleTemplateArgs(args);
				ApplyTemplateArgs(type, std::move(args));
				typeRef = nullptr;
				substitute = true;
			}
		}
		else
		{
			if (m_reader.ConsumeIf('t'))
			{
				type = DemangleUnqualifiedName();
				DemangledQualifiedName qn = type.GetName();
				qn.insert(qn.begin(), DemangledNamePart("std"));
				type.SetName(std::move(qn));
				substitute = true;
			}
			else
			{
				type = DemangleSubstitution(&typeRef);
			}
			if (m_reader.ConsumeIf('I'))
			{
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
		if (m_reader.ConsumeIf('s'))
		{
			type = DemangledTypeNode::NamedType(StructNamedTypeClass, DemangleSourceName());
			break;
		}
		else if (m_reader.ConsumeIf('u'))
		{
			type = DemangledTypeNode::NamedType(UnionNamedTypeClass, DemangleSourceName());
			break;
		}
		else if (m_reader.ConsumeIf('e'))
		{
			type = DemangledTypeNode::NamedType(
				EnumNamedTypeClass, DemangleSourceName(), m_platform.get().GetArchitecture()->GetDefaultIntegerSize());
			break;
		}

		//Template Substitution
		type = DemangleTemplateSubstitution(&typeRef);
		// In forward-ref mode (cv conversion operator type parsing), do not consume
		// trailing I<args>E — it belongs to the enclosing nested-name and will be
		// processed by DemangleNestedName's 'I' case, which resolves forward refs.
		substitute = !m_permitForwardTemplateRefs && !typeRef.IsTemplateParamPack();
		if (!m_permitForwardTemplateRefs && m_reader.ConsumeIf('I'))
		{
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
		if (m_reader.ConsumeIf('I'))
		{
			ParamList targs;
			DemangleTemplateArgs(targs);
			if (!targs.empty())
				extName.SetTemplateArguments(std::move(targs), true);
		}
		DemangledTypeNode inner = DemangleType();
		NodeRef innerRef = m_lastTypeRef ? m_lastTypeRef : NodeRef(DemangledTypeNode::CreateShared(std::move(inner)));
		auto extType = DemangledTypeNode::NamedType(DemangledQualifiedName{std::move(extName)});
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
		if (m_reader.ConsumeIf('I'))
		{
			ParamList targs;
			DemangleTemplateArgs(targs);
			if (!targs.empty())
				extName.SetTemplateArguments(std::move(targs), true);
		}
		type = DemangledTypeNode::NamedType(DemangledQualifiedName{std::move(extName)});
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
		NodeRef memberNameRef = m_lastTypeRef ? m_lastTypeRef : NodeRef(DemangledTypeNode::CreateShared(std::move(memberName)));
		DemangledTypeNode member = DemangleType();
		NodeRef memberRef = m_lastTypeRef ? m_lastTypeRef : NodeRef(DemangledTypeNode::CreateShared(std::move(member)));
		type = DemangledTypeNode::MemberPointerType(memberRef, memberNameRef->GetName(), cnst, vltl);
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
		case 'u': type = DemangledTypeNode::IntegerType(1, false, "char8_t"); break;
		case 'i': type = DemangledTypeNode::WideCharType(4, "char32_t"); break;
		case 's': type = DemangledTypeNode::WideCharType(2, "char16_t"); break;
		case 'a': type = DemangledTypeNode::NamedType("auto"); break; //auto type
		case 'c': type = DemangledTypeNode::NamedType("decltype(auto)"); break; //decltype(auto)
		case 'n':
		{
			static const StringList stdNullptrTName(vector<string>{"std", "nullptr_t"});
			type = DemangledTypeNode::NamedType(stdNullptrTName);
			break;
		}
		case 'p':
		{
			DemangledTypeNode inner = DemangleType();
			NodeRef innerRef = (m_lastTypeRef || m_lastTypeRef.IsTemplateParamPack()) ?
				m_lastTypeRef : NodeRef(DemangledTypeNode::CreateShared(std::move(inner)));
			if (innerRef.IsTemplateParamPack())
			{
				typeRef = NodeRef::TemplateParamPackExpansion(*innerRef.templatePack);
				type = typeRef ? *typeRef : DemangledTypeNode::VoidType();
				break;
			}
			type = DemangledTypeNode::PostfixType(innerRef, "...");
			break;
		}
		case 't':
		case 'T':
			type = DemangledTypeNode::NamedType("decltype(" + DemangleExpression() + ")");
			if (!m_reader.ConsumeIf('E'))
				throw DemangleException();
			break;
		case 'v':
		{
			// vector of size
			uint64_t size = DemangleNumber();
			if (!m_reader.ConsumeIf('_'))
				throw DemangleException();
			NodeRef childRef = nullptr;
			DemangledTypeNode child = DemangleType();
			childRef = m_lastTypeRef;
			type = childRef ? DemangledTypeNode::ArrayType(childRef, size) :
				DemangledTypeNode::ArrayType(std::move(child), size);
			break;
		}
		default:
			LogWithIndentation("Unsupported type: %s:'%s'\n", __FUNCTION__, m_reader.GetRaw());
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
		if (isdigit(m_reader.PeekOr()))
		{
			//<positive dimension number> _ <element type>
			uint64_t size = DemangleNumber();
			if (!m_reader.ConsumeIf('_'))
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
			if (m_reader.PeekOr() != '_')
			{
				dimension = "[" + DemangleExpression() + "]";
			}
			if (!m_reader.ConsumeIf('_'))
				throw DemangleException();

			DemangledTypeNode inner = DemangleType();
			NodeRef innerRef = m_lastTypeRef ? m_lastTypeRef : NodeRef(DemangledTypeNode::CreateShared(std::move(inner)));
			type = DemangledTypeNode::PostfixType(innerRef, std::move(dimension));
		}
		substitute = true;
		break;
	default:
	{
		m_reader.UnRead();

		type = DemangleName();
		std::string_view lastName = LastTypeNameSegmentBase(type);
		if (lastName.empty())
			throw DemangleException();
		m_lastName = lastName;
		substitute = true;

		if (m_reader.ConsumeIf('I'))
		{
			substitute = false;
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

	LOG_INDENTATION_SCOPE;
	LogWithIndentation("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw());
	char elm = m_reader.Read();
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
			size_t base36 = isdigit(elm) ? static_cast<size_t>(elm - '0') : static_cast<size_t>(elm - 'A' + 10);
			while (m_reader.PeekOr() != '_')
			{
				char c = m_reader.Read();
				if (isdigit(c))
					base36 = base36 * 36 + static_cast<size_t>(c - '0');
				else if (isupper(c))
					base36 = base36 * 36 + static_cast<size_t>(c - 'A' + 10);
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

		if (!m_reader.ConsumeIf('_'))
		{
			throw DemangleException();
		}
		NodeRef ref;
		if (number < m_substitute.size())
		{
			ref = GetTypeRef(number);
		}
		else if (number == m_substitute.size() && m_reader.PeekOr() == 'I' && !m_substitute.empty())
		{
			// GNU/libstdc++ pack expansions can elide an empty template-id that
			// LLVM still effectively treats as occupying this substitution slot.
			// When the next production immediately replaces template arguments,
			// use the previous template-id as the prefix.
			if (m_substitute.back().emptyTemplatePack || !m_substitute.back())
				throw DemangleException();
			ref = m_substitute.back();
		}
		else
		{
			ref = GetTypeRef(number);
		}
		const DemangledTypeNode& resolved = *ref;
		std::string_view lastName = LastTypeNameSegmentBase(resolved);
		if (!lastName.empty())
			m_lastName = lastName;
		if (outTypeRef)
			*outTypeRef = ref;
		return resolved;
	}
	m_lastName = name.back();
	return DemangledTypeNode::NamedType(std::move(name));
}

string DemangleGNU3::DemangleNumberAsString()
{
	bool negativeFactor = false;
	if (m_reader.ConsumeIf('n'))
	{
		negativeFactor = true;
	}

	string number;
	while (isdigit(m_reader.PeekOr()))
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
	if (m_reader.ConsumeIf('n'))
	{
		negative = true;
	}

	if (!isdigit(m_reader.PeekOr()))
		throw DemangleException();

	int64_t result = 0;
	do
	{
		result = result * 10 + (m_reader.Read() - '0');
	} while (isdigit(m_reader.PeekOr()));
	return negative ? -result : result;
}


string DemangleGNU3::DemanglePrimaryExpression()
{
	LOG_INDENTATION_SCOPE;
	LogWithIndentation("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw());
	char elm1 = '\0';
	string out;
	StringList tmpList;
	bool oldTopLevel;
	//expr-primary
	if (m_reader.ConsumeIf("_Z"))
	{
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
		out += t.GetTypeAndName(tmpList, m_platform);
		return out;
	}
	// LZ<encoding>E: function address template arg (GCC/Clang, without leading underscore)
	if (m_reader.ConsumeIf('Z'))
	{
		auto savedTemplateSubstitute2 = m_templateSubstitute;
		m_templateSubstitute.clear();
		oldTopLevel = m_topLevel;
		m_topLevel = true;
		DemangledTypeNode t2 = DemangleSymbol(tmpList);
		m_topLevel = oldTopLevel;
		m_templateSubstitute = std::move(savedTemplateSubstitute2);
		out += t2.GetTypeAndName(tmpList, m_platform);
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
	if (!m_reader.ConsumeIf('E'))
		throw DemangleException();
	return out;
}


string DemangleGNU3::DemangleUnarySuffixExpression(std::string_view op)
{
	string out = "(" + DemangleExpression() + ")";
	out += op;
	return out;
}


string DemangleGNU3::DemangleUnaryPrefixExpression(std::string_view op, DemangledTypeNode* outNode)
{
	DemangledTypeNode exprNode;
	string expr = DemangleExpression(outNode ? &exprNode : nullptr);
	if (outNode)
	{
		if (exprNode.GetClass() == VoidTypeClass)
			exprNode = DemangledTypeNode::NamedType(expr);
		*outNode = DemangledTypeNode::UnaryExpression(
			string(op), DemangledTypeNode::CreateShared(std::move(exprNode)));
	}
	string out(op);
	out += "(";
	out += expr;
	out += ")";
	return out;
}


string DemangleGNU3::DemangleBinaryExpression(std::string_view op, DemangledTypeNode* outNode)
{
	LOG_INDENTATION_SCOPE;
	LogWithIndentation("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw());
	DemangledTypeNode lhsNode;
	DemangledTypeNode rhsNode;
	const string lhsExpr = DemangleExpression(outNode ? &lhsNode : nullptr);
	const string rhsExpr = DemangleExpression(outNode ? &rhsNode : nullptr);
	const string lhs = "(" + lhsExpr + ")";
	const string rhs = "(" + rhsExpr + ")";
	if (outNode)
	{
		if (lhsNode.GetClass() == VoidTypeClass)
			lhsNode = DemangledTypeNode::NamedType(lhsExpr);
		if (rhsNode.GetClass() == VoidTypeClass)
			rhsNode = DemangledTypeNode::NamedType(rhsExpr);
		*outNode = DemangledTypeNode::BinaryExpression(
			DemangledTypeNode::CreateShared(std::move(lhsNode)), string(op),
			DemangledTypeNode::CreateShared(std::move(rhsNode)));
	}
	string out = lhs;
	out += " ";
	out += op;
	out += " ";
	out += rhs;
	return out;
}


string DemangleGNU3::DemangleUnaryPrefixType(std::string_view op)
{
	string out(op);
	out += "(";
	out += DemangleTypeString();
	out += ")";
	return out;
}


string DemangleGNU3::DemangleTypeString()
{
	return DemangleType().GetString();
}


string DemangleGNU3::DemangleExpressionList()
{
	LOG_INDENTATION_SCOPE;
	LogWithIndentation("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw());
	string expr;
	bool first = true;
	m_functionSubstitute.emplace_back();
	while (!m_reader.ConsumeIf('E'))
	{
		if (!first)
			expr += ", ";
		const string e = DemangleExpression();
		expr += e;
		m_functionSubstitute.back().emplace_back(
			DemangledTypeNode::CreateShared(DemangledTypeNode::NamedType(e)));
		first = false;
	}
	m_functionSubstitute.pop_back();
	return expr;
}


DemangledTypeNode DemangleGNU3::DemangleUnqualifiedName()
{
	LOG_INDENTATION_SCOPE;
	LogWithIndentation("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw());

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
	{
		string name = "operator";
		name += GetOperator(elm1, elm2);
		outType = DemangledTypeNode::NamedType(name);
		outType.SetNameType(GetNameType(elm1, elm2));
		break;
	}
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
	{
		string name = "operator ";
		name += GetOperator(elm1, elm2);
		outType = DemangledTypeNode::NamedType(name);
		outType.SetNameType(GetNameType(elm1, elm2));
		break;
	}
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
		outType = DemangledTypeNode::NamedType(m_lastName);
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
		outType = DemangledTypeNode::NamedType(m_lastName);
		outType.SetNameType(ConstructorNameType);
		break;
	}
	case hash('D','0'): //Destructor
	case hash('D','1'):
	case hash('D','2'):
	case hash('D','3'):
	case hash('D','4'):
	case hash('D','5'):
		outType = DemangledTypeNode::NamedType("~" + m_lastName);
		outType.SetNameType(DestructorNameType);
		break;
	case hash('D','t'):
	case hash('D','T'):
		outType = DemangledTypeNode::NamedType(DemangleExpression());
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
		}while (m_reader.PeekOr() != 'E');
		if (!m_reader.ConsumeIf('E'))
			throw DemangleException();
		m_parsingLambdaParams = savedParsingLambdaParams;
		m_lambdaTemplateParamBase = savedLambdaTemplateParamBase;

		if (isdigit(m_reader.PeekOr()))
		{
			name += DemangleNumberAsString();
		}
		if (!m_reader.ConsumeIf('_'))
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
		outType = DemangledTypeNode::NamedType(name);
		PushType(outType);
		break;
	}
	case hash('U','t'):
	{
		string name;
		name = "'unnamed";

		if (isdigit(m_reader.PeekOr()))
		{
			name += DemangleNumberAsString();
		}
		name += "\'";

		if (!m_reader.ConsumeIf('_'))
			throw DemangleException();

		m_lastName = name;
		outType = DemangledTypeNode::NamedType(name);
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
		NodeRef cvTypeRef = m_lastTypeRef ? m_lastTypeRef : NodeRef(DemangledTypeNode::CreateShared(std::move(cvType)));
		m_permitForwardTemplateRefs = savedPermit;
		outType = DemangledTypeNode::NamedType(DemangledQualifiedName{DemangledNamePart("operator ", std::move(cvTypeRef))});
		break;
	}
	default:
		m_reader.UnRead(2);
		if (isdigit(m_reader.PeekOr()) || m_reader.ConsumeIf('L'))
		{
			string name(DemangleSourceName());
			if (name.size() > 11 && name.substr(0, 11) == "_GLOBAL__N_")
				name = "(anonymous namespace)";
			m_lastName = name;
			outType = DemangledTypeNode::NamedType(name);
		}
		else
		{
			throw DemangleException();
		}
	}
	// Consume ABI tags: B <source-name>  =>  [abi:tagname]
	// Applies to source names, operator names, and unnamed types.
	while (m_reader.ConsumeIf('B'))
	{
		string tag = "[abi:";
		tag.append(DemangleSourceName());
		tag += "]";
		ExtendTypeName(outType, tag);
		std::string_view lastName = LastTypeNameSegmentBase(outType);
		m_lastName = lastName.empty() ? tag : string(lastName);
	}
	return outType;
}


StringList DemangleGNU3::DemangleBaseUnresolvedName()
{
	// <base-unresolved-name> ::= <simple-id>                                # unresolved name
	//                        ::= on <operator-name>                         # unresolved operator-function-id
	//                        ::= on <operator-name> <template-args>         # unresolved operator template-id
	//                        ::= dn <destructor-name>                       # destructor or pseudo-destructor;
	//                                                                       # e.g. ~X or ~X<N-1>

	LOG_INDENTATION_SCOPE;
	LogWithIndentation("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw());
	StringList out;
	if (m_reader.Length() > 1)
	{
		if (m_reader.ConsumeIf("on"))
		{
			char op1 = m_reader.Read();
			char op2 = m_reader.Read();
			out.emplace_back(GetOperator(op1, op2));
			if (m_reader.ConsumeIf('I'))
			{
				ParamList args;
				DemangleTemplateArgs(args);
				out.back() = NameSegmentWithTemplateArgs(out.back(), std::move(args)).GetString();
				PushType(DemangledTypeNode::NamedType(out));
			}
		}
		else if (m_reader.PeekMatch("dn"))
		{
			string name = DemangleUnresolvedType().GetString();
			if (name.empty())
			{
				string dtorName = "~";
				dtorName.append(DemangleSourceName());
				out.push_back(std::move(dtorName));
			}
			else
				out.push_back("~" + name);
		}
		else
		{
			// <simple-id>
			out.emplace_back(DemangleSourceName());
			if (m_reader.ConsumeIf('I'))
			{
				ParamList args;
				DemangleTemplateArgs(args);
				out.back() = NameSegmentWithTemplateArgs(out.back(), std::move(args)).GetString();
			}
		}
	}
	return out;
}


DemangledTypeNode DemangleGNU3::DemangleUnresolvedType()
{
	LOG_INDENTATION_SCOPE;
	LogWithIndentation("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw());
	//<unresolved-type> ::= <template-param> [ <template-args> ]            # T:: or T<X,Y>::
	//                  ::= <decltype>                                      # decltype(p)::
	//                  ::= <substitution>
	DemangledTypeNode type;
	if (m_reader.ConsumeIf('T'))
	{
		type = DemangleTemplateSubstitution();
		if (m_reader.ConsumeIf('I'))
		{
			PushType(type);
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
	else if (m_reader.Length() > 2 && (m_reader.ConsumeIf("Dt") || m_reader.ConsumeIf("DT")))
	{
		const string name = "decltype(" + DemangleExpression() + ")";
		if (!m_reader.ConsumeIf('E'))
			throw DemangleException();
		type = DemangledTypeNode::NamedType(name);
	}
	else if (m_reader.ConsumeIf('S'))
	{
		type = DemangleSubstitution();
	}
	else
	{
		throw DemangleException();
	}
	return type;
}


string DemangleGNU3::DemangleExpression(DemangledTypeNode* outNode)
{
	LogWithIndentation("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw());
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
		DemangledTypeNode type = DemangleTemplateSubstitution();
		if (outNode)
			*outNode = type;
		return type.GetString();
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
		std::string_view op = GetOperator(elm1, elm2);
		const string castType = DemangleTypeString();
		const string castExpr = DemangleExpression();
		return string(op) + "<" + castType + ">(" + castExpr + ")";
	}
	case hash('t','i'):
	case hash('t','e'):
	case hash('s','t'):
	case hash('s','z'):
	case hash('a','t'):
	case hash('a','z'):
	case hash('n','x'):
	case hash('s','Z'):
		return string(GetOperator(elm1, elm2)) + "(" + DemangleExpression() + ")";
	case hash('s','P'):
	{
		ParamList args;
		DemangleTemplateArgs(args);
		return "sizeof...(" + NameSegmentWithTemplateArgs("", std::move(args)).GetString() + ")...";
	}
	case hash('s','p'):
		return "(" + DemangleExpression() + ")...";
	case hash('t','w'):
		return string(GetOperator(elm1, elm2)) + DemangleExpression();
	case hash('t','r'):
		return string(GetOperator(elm1, elm2)); //rethrow
	case hash('n','t'): // !
	case hash('n','g'): // - (unary)
	case hash('p','s'): // + (unary)
	case hash('a','d'): // & (unary)
	case hash('d','e'): // * (unary)
		return DemangleUnaryPrefixExpression(GetOperator(elm1, elm2), outNode);
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
		return DemangleBinaryExpression(GetOperator(elm1, elm2), outNode);
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
		m_functionSubstitute.emplace_back();
		while (!m_reader.ConsumeIf('E'))
		{
			if (!firstArg) args += ", ";
			const string e = DemangleExpression();
			args += e;
			m_functionSubstitute.back().emplace_back(
				DemangledTypeNode::CreateShared(DemangledTypeNode::NamedType(e)));
			firstArg = false;
		}
		m_functionSubstitute.pop_back();
		return callable + "(" + args + ")";
	}
	case hash('c','v'): //type (expression)
	{
		DemangledTypeNode type = DemangleType();
		out = type.GetString();
		if (m_reader.ConsumeIf('_'))
		{
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
		if (!m_reader.ConsumeIf('E'))
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
			if (listNumber < 0 || !m_reader.ConsumeIf('p'))
				throw DemangleException();
		}
		DemangleCVQualifiers(cnst, vltl, rstrct);
		elm = m_reader.PeekOr();
		if (m_reader.ConsumeIf('_'))
		{
			if (static_cast<uint64_t>(listNumber) >= static_cast<uint64_t>(m_functionSubstitute.size()) ||
			    static_cast<uint64_t>(elementNum) >= m_functionSubstitute[listNumber].size())
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
			if (!m_reader.ConsumeIf('_'))
				throw DemangleException();
			if (elementNum < 0 ||
			    static_cast<uint64_t>(listNumber) >= static_cast<uint64_t>(m_functionSubstitute.size()) ||
			    static_cast<size_t>(elementNum) >= m_functionSubstitute[listNumber].size())
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
		if (outNode)
			*outNode = type;
		break;
	}
	case hash('s','r'):
	{
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
		DemangledQualifiedName structuredName;
		if (m_reader.ConsumeIf('N'))
		{
			// Standard form: N <unresolved-type> <qualifier-levels>+ E <base>
			// where <unresolved-type> is T_, Dt, or S.
			// GCC extension: N <source-name-qualifier>+ E <base>
			// When the first component is a digit (source name), skip the
			// unresolved-type and let the loop below handle all qualifiers.
			if (!isdigit(m_reader.PeekOr()))
			{
				DemangledTypeNode unresolvedType = DemangleUnresolvedType();
				out += unresolvedType.GetString() + "::";
				AppendStructuredNameSegments(structuredName, unresolvedType.RenderTypeNameSegments());
			}
			do
			{
				std::string_view segName = DemangleSourceName();
				const size_t segmentStart = out.size();
				out.append(segName);
				DemangledNamePart structuredSegment(segName);
				// Push bare name (before template args) to substitution table.
				PushType(DemangledTypeNode::NamedType(StringList{out}));
				if (m_reader.ConsumeIf('I'))
				{
					ParamList args;
					//<tmplate-args>
					DemangleTemplateArgs(args);
					structuredSegment = NameSegmentWithTemplateArgs(segName, std::move(args));
					out.resize(segmentStart);
					out += structuredSegment.GetString();
					// Also push the template instantiation (name+args).
					PushType(DemangledTypeNode::NamedType(StringList{out}));
				}
				structuredName.push_back(std::move(structuredSegment));
				out += "::";
			}while (!m_reader.ConsumeIf('E'));

			StringList baseName = DemangleBaseUnresolvedName();
			out += JoinNameSegments(baseName);
			AppendStructuredNameSegments(structuredName, baseName);
			SetStructuredExpressionNode(outNode, structuredName);
			return out;
		}
		if (isdigit(m_reader.PeekOr()))
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
				std::string_view segName = DemangleSourceName();
				const size_t segmentStart = out.size();
				out.append(segName);
				DemangledNamePart structuredSegment(segName);
				// Push bare name to substitution table.
				PushType(DemangledTypeNode::NamedType(out));
				if (m_reader.ConsumeIf('I'))
				{
					ParamList args;
					DemangleTemplateArgs(args); // consumes the trailing 'E'
					structuredSegment = NameSegmentWithTemplateArgs(segName, std::move(args));
					out.resize(segmentStart);
					out += structuredSegment.GetString();
					// Also push the template instantiation.
					PushType(DemangledTypeNode::NamedType(out));
					hadTemplateArgs = true;
				}
				structuredName.push_back(std::move(structuredSegment));
				out += "::";
			}while (!hadTemplateArgs && m_reader.PeekOr() != 'E');
			// Consume qualifier-list 'E' if present. GCC sometimes omits it when
			// the last qualifier had template-args whose 'E' served double duty,
			// so check rather than unconditionally consuming.
			m_reader.ConsumeIf('E');
			StringList baseName = DemangleBaseUnresolvedName();
			out += JoinNameSegments(baseName);
			AppendStructuredNameSegments(structuredName, baseName);
			SetStructuredExpressionNode(outNode, structuredName);
			return out;
		}
		else
		{
			DemangledTypeNode unresolvedType = DemangleUnresolvedType();
			out += unresolvedType.GetString() + "::";
			AppendStructuredNameSegments(structuredName, unresolvedType.RenderTypeNameSegments());
			// GCC may encode multi-level scoped names without the 'N' qualifier
			// prefix, e.g. "sr St 6__and_I<T>E 5value" for std::__and_<T>::value.
			// Process any digit-started names: if a name has template args AND
			// another source name follows, it is an intermediate qualifier level;
			// otherwise it is the final base-unresolved-name.
			while (isdigit(m_reader.PeekOr()))
			{
				std::string_view segName = DemangleSourceName();
				if (m_reader.ConsumeIf('I'))
				{
					ParamList args;
					DemangleTemplateArgs(args);
					DemangledNamePart structuredSegment = NameSegmentWithTemplateArgs(segName, args);
					if (isdigit(m_reader.PeekOr()))
					{
						// Another source name follows — intermediate qualifier.
						// Push to the substitution table, mirroring what the
						// N-prefix sr branch does for each nested qualifier.
						string segment = NameSegmentWithTemplateArgs(segName, std::move(args)).GetString();
						PushType(DemangledTypeNode::NamedType(out + segment));
						out += segment + "::";
						structuredName.push_back(std::move(structuredSegment));
					}
					else
					{
						// No more source names — this template-id is the final name.
						out += NameSegmentWithTemplateArgs(segName, std::move(args)).GetString();
						structuredName.push_back(std::move(structuredSegment));
						SetStructuredExpressionNode(outNode, structuredName);
						return out;
					}
				}
				else
				{
					// Plain source name with no template args — final base name.
					out.append(segName);
					structuredName.emplace_back(segName);
					SetStructuredExpressionNode(outNode, structuredName);
					return out;
				}
			}
			// peek is not a digit: fall back for operator-names ("on") / destructor-names ("dn").
			StringList baseName = DemangleBaseUnresolvedName();
			out += JoinNameSegments(baseName);
			AppendStructuredNameSegments(structuredName, baseName);
			SetStructuredExpressionNode(outNode, structuredName);
		}
		return out;
	}
	default:
		m_reader.UnRead(2);
		out = DemangleSourceName();
		DemangledNamePart structuredSegment(out);
		if (m_reader.ConsumeIf('I'))
		{
			ParamList args;
			//<tmplate-args>
			DemangleTemplateArgs(args);
			structuredSegment = NameSegmentWithTemplateArgs(out, std::move(args));
			out = structuredSegment.GetString();
		}
		if (outNode)
			*outNode = DemangledTypeNode::NamedType(DemangledQualifiedName{std::move(structuredSegment)});
		break;
	}
	return out;
}


bool DemangleGNU3::TryDemangleTemplateParamExpressionPackExpansion(string& expr, bool& emptyPack)
{
	if (!m_reader.ConsumeIf("spT"))
		return false;

	NodeRef entry = DemangleTemplateSubstitutionEntry();
	if (entry.emptyTemplatePack)
	{
		emptyPack = true;
		return true;
	}
	if (!entry)
		throw DemangleException();

	expr = entry->GetString();
	return true;
}


bool DemangleGNU3::AppendTemplateParamPackExpansion(ParamList& params, const NodeRef& expansion, bool functionParameter)
{
	if (!expansion.IsTemplateParamPackExpansion())
		return false;

	if (expansion.emptyTemplatePack)
	{
		m_substitute.emplace_back(NodeRef::EmptyTemplatePack());
		return true;
	}

	for (const auto& arg : *expansion.templatePack)
	{
		if (!arg.type)
			throw DemangleException();
		NodeRef paramRef = PushType(*arg.type);
		m_lastTypeRef = paramRef;
		if (functionParameter && !m_functionSubstitute.empty())
			m_functionSubstitute.back().push_back(paramRef);
		params.push_back({"", paramRef});
	}
	return true;
}


bool DemangleGNU3::DemangleTemplateArg(ParamList& args, bool* hadNonTypeArg)
{
	DemangledTypeNode tmp;
	NodeRef tmpRef;
	bool tmpValid = false;
	bool topLevel;
	switch (m_reader.Read())
	{
	case 'L':
	{
		string expr;
		expr = DemanglePrimaryExpression();
		tmp = DemangledTypeNode::NamedType(expr);
		tmpRef = DemangledTypeNode::CreateShared(std::move(tmp));
		args.push_back({"", tmpRef});
		tmpValid = true;
		if (hadNonTypeArg)
			*hadNonTypeArg = true;
		break;
	}
	case 'X':
	{
		string expr;
		DemangledTypeNode exprNode;
		bool haveExprNode = false;
		bool emptyPack = false;
		if (!TryDemangleTemplateParamExpressionPackExpansion(expr, emptyPack))
		{
			expr = DemangleExpression(&exprNode);
			haveExprNode = true;
		}
		if (!emptyPack)
		{
			if (!haveExprNode || exprNode.GetClass() == VoidTypeClass)
				exprNode = DemangledTypeNode::NamedType(expr);
			args.push_back({"", DemangledTypeNode::CreateShared(std::move(exprNode))});
		}
		if (!m_reader.ConsumeIf('E'))
			throw DemangleException();
		if (hadNonTypeArg) *hadNonTypeArg = true;
		break;
	}
	case 'I': // GCC sometimes uses I...E for argument packs instead of J...E
	case 'J':
	{
		size_t prevTemplateSize = m_templateSubstitute.size();
		size_t prevArgSize = args.size();
		DemangleTemplateArgs(args, hadNonTypeArg);
		if (m_topLevel)
		{
			ParamList packArgs(args.begin() + prevArgSize, args.end());
			while (m_templateSubstitute.size() > prevTemplateSize)
				m_templateSubstitute.pop_back();
			m_templateSubstitute.emplace_back(NodeRef::TemplateParamPack(std::move(packArgs)));
		}
		break;
	}
	case 'T':
		if (m_reader.ConsumeIf('n'))
		{
			// <template-arg> ::= <template-param-decl> <template-arg>
			// <template-param-decl> ::= Tn <type>  # non-type parameter
			//
			// The declaration names a synthetic non-type template parameter
			// for the following argument. Binary Ninja does not print those
			// synthetic parameter names, so consume the declaration type and
			// keep only the actual following template argument.
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
		if (AppendTemplateParamPackExpansion(args, m_lastTypeRef, false))
			return true;
		tmpRef = DemangledTypeNode::CreateShared(std::move(tmp));
		args.push_back({"", tmpRef});
		tmpValid = true;
	}
	if (m_topLevel && tmpValid)
	{
		LogWithIndentation("Adding template ref: %s\n", tmpRef ? tmpRef->GetString().c_str() : "");
		m_templateSubstitute.emplace_back(tmpRef);
	}
	return true;
}


void DemangleGNU3::DemangleTemplateArgs(ParamList& args, bool* hadNonTypeArg)
{
	NestingGuard nestingGuard(m_nestingDepth);
	LOG_INDENTATION_SCOPE;
	LogWithIndentation("%s:: '%s'\n", __FUNCTION__, m_reader.GetRaw());
	const string lastName = m_lastName;
	while (!m_reader.ConsumeIf('E'))
	{
		if (!DemangleTemplateArg(args, hadNonTypeArg))
			break;
	}
	m_lastName = lastName;
}


DemangledTypeNode DemangleGNU3::DemangleNestedName(bool* allTypeTemplateArgs, bool pushBareTemplatePrefix)
{
	NestingGuard nestingGuard(m_nestingDepth);
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

	LOG_INDENTATION_SCOPE;
	LogWithIndentation("%s:: '%s'\n", __FUNCTION__, m_reader.GetRaw());
	DemangledTypeNode type = DemangledTypeNode::NamedType(StringList{});
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
	if (m_reader.ConsumeIf('R'))
	{
		ref = true;
	}
	else if (m_reader.ConsumeIf('O'))
	{
		ref = true;
		rvalueRef = true;
	}

	while (!m_reader.ConsumeIf('E'))
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
		while (m_reader.ConsumeIf('B'))
		{
			string savedLastName = m_lastName;
			string abiTag(DemangleSourceName());
			m_lastName = savedLastName;
			ExtendTypeName(type, "[abi:" + abiTag + "]");
		}
		bool dependentTemplatePrefix = !pushBareTemplatePrefix && m_reader.PeekOr() == 'I' &&
			LastTypeNameSegmentBase(type) == "basic_ostream" &&
			TemplateArgsReferenceTemplateParam(m_reader.PeekString(m_reader.Length()));
		if (substitute && m_reader.PeekOr() != 'E' && !dependentTemplatePrefix)
		{
			//Those template arguments were not the primary arguments so clear them from the sub listType
			while (m_templateSubstitute.size() > startSize)
			{
				m_templateSubstitute.pop_back();
			}
			PushType(type);
		}
		LogWithIndentation("%s:: '%s'\n", __FUNCTION__, m_reader.GetRaw());
	}

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
	return type;
}


DemangledTypeNode DemangleGNU3::DemangleLocalName()
{
	NestingGuard nestingGuard(m_nestingDepth);
	LOG_INDENTATION_SCOPE;
	LogWithIndentation("%s '%s'\n", __FUNCTION__, m_reader.GetRaw());
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

	if (!varName.empty())
		varName.back() += type.GetStringAfterName(m_platform);
	else
		varName.push_back(type.GetString());

	if (!m_reader.ConsumeIf('s'))
	{
		// Handle default argument context: d [<number>] _ <name>
		if (m_reader.ConsumeIf('d'))
		{
			if (isdigit(m_reader.PeekOr()))
				DemangleNumber();
			m_reader.ConsumeIf('_');
		}
		//<entity name>
		DemangledTypeNode tmpType = DemangleName();
		type = DemangledTypeNode::NamedType(varName);
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
		type = DemangledTypeNode::NamedType(varName);
		m_templateSubstitute = std::move(savedTemplateSubstitute);
		m_topLevel = oldTopLevel;
	}
	// [<discriminator>]
	//TODO: What do we do with discriminators?
	if (m_reader.ConsumeIf('_'))
	{
		if (m_reader.ConsumeIf('_'))
		{
			DemangleNumberAsString();
			if (!m_reader.ConsumeIf('_'))
				throw DemangleException();
		}
		else
		{
			DemangleNumberAsString();
		}
	}
	return type;
}


DemangledTypeNode DemangleGNU3::DemangleName()
{
	NestingGuard nestingGuard(m_nestingDepth);
	LOG_INDENTATION_SCOPE;
	LogWithIndentation("%s '%s'\n", __FUNCTION__, m_reader.GetRaw());
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
		if (m_reader.ConsumeIf('t'))
		{
			type = DemangleUnqualifiedName();
			DemangledQualifiedName qn = type.GetName();
			qn.insert(qn.begin(), DemangledNamePart("std"));
			type.SetName(std::move(qn));
			substitute = true;
		}
		else
		{
			type = DemangleSubstitution();
		}

		if (m_reader.ConsumeIf('I'))
		{
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
		m_reader.ConsumeIf('L');
		type = DemangleUnqualifiedName();
		if (m_reader.ConsumeIf('I'))
		{
			PushType(type);
			//<unscoped-template-name>
			ParamList args;
			//<tmplate-args>
			DemangleTemplateArgs(args);
			ApplyTemplateArgs(type, std::move(args));
		}
	}
	return type;
}


DemangledTypeNode DemangleGNU3::DemangleSymbol(StringList& varName, bool simplifyTemplates)
{
	NestingGuard nestingGuard(m_nestingDepth);
	LOG_INDENTATION_SCOPE;
	LogWithIndentation("%s: %s\n", __FUNCTION__, m_reader.GetRaw());
	DemangledTypeNode returnType;
	NodeRef returnTypeRef = nullptr;
	bool isReturnTypeUnknown = false;
	DemangledTypeNode type;
	ParamList params;
	bool cnst = false, vltl = false;
	bool oldTopLevel;
	StringList name;

	/*
	<encoding> ::= <function name> <bare-function-type>
	           ::= <data name>
	           ::= <special-name>
	*/
	//<special-name>
	switch (m_reader.PeekOr())
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
			while (m_reader.Length() > 0 && !m_reader.ConsumeIf('_'))
				seqId += m_reader.Read();
			string result = "reference_temporary_for_" + nameNode.GetString();
			if (!seqId.empty())
				result += "[" + seqId + "]";
			varName.push_back(result);
			return DemangledTypeNode::NamedType(varName);
		}
		case 'T': // transaction clone: GTt<encoding> (safe) or GTn<encoding> (non-safe)
		{
			// consume the 't' (transaction-safe) or 'n' (non-transaction-safe) qualifier
			char kind = m_reader.Read();
			if (kind != 't' && kind != 'n')
				throw DemangleException();
			oldTopLevel = m_topLevel;
			m_topLevel = false;
			DemangledTypeNode t = DemangleSymbol(name, simplifyTemplates);
			m_topLevel = oldTopLevel;
			return DemangledTypeNode::NamedType(StringList{JoinNameSegments(name) + " [transaction clone]" + t.GetStringAfterName(m_platform)});
		}
		case 'V':
		{
			// Disambiguate: Intel Vector Function ABI (_ZGV<isa>...) vs guard variable (_ZGV<symbol>).
			// Intel Vector ABI isa codes: b c d e x y Y z Z
			// Guard variable encoding starts with: N (nested), L (local), S (substitution), digit, etc.
			char peekChar = m_reader.PeekOr();
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
				_STD_STRING ahead = m_reader.PeekString(std::min(static_cast<size_t>(32), m_reader.Length()));
				if (ahead.size() >= 3 && (ahead[1] == 'M' || ahead[1] == 'N'))
				{
					size_t pos = 2;
					while (pos < ahead.size() && isdigit(static_cast<unsigned char>(ahead[pos])))
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
							    c == 'L' || c == 's' || isdigit(static_cast<unsigned char>(c)))
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
				DemangledTypeNode t = DemangleSymbol(name, simplifyTemplates);
				varName.push_back("guard_variable_for_" + t.GetTypeAndName(name, m_platform));
				type = DemangledTypeNode::IntegerType(1, false);
				if (m_reader.Length() == 0)
					return type;
				//function parameters
				string paramList;
				paramList += "(";
				bool first = true;
				do
				{
					if (m_reader.ConsumeIf('v'))
					{
						break;
					}
					if (!first)
						paramList += ", ";
					paramList += DemangleTypeString();
				}while (m_reader.PeekOr() != 'E');
				if (!m_reader.ConsumeIf('E'))
					throw DemangleException();
				varName.back() += paramList + ")";
				varName.emplace_back(DemangleSourceName());

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
			if (!isdigit(m_reader.PeekOr()))
				throw DemangleException();
			string vlenStr;
			while (isdigit(m_reader.PeekOr()))
				vlenStr += m_reader.Read();

			// Parse vparameters until '_' separator
			// <vparameter> <opt-align>
			// <vparameter> ::= ('l'|'R'|'U'|'L') <stride>  |  'u'  |  'v'
			// <stride>     ::= empty | 's' <decimal> | <number>
			// <opt-align>  ::= empty | 'a' <decimal>
			string paramsStr;
			bool firstParam = true;
			while (m_reader.Length() > 0 && m_reader.PeekOr() != '_')
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
					if (m_reader.ConsumeIf('s'))
					{
						// linear_step passed as another argument at given 0-based position
						string argPos;
						while (isdigit(m_reader.PeekOr()))
							argPos += m_reader.Read();
						paramsStr += "(step=arg" + argPos + ")";
					}
					else if (isdigit(m_reader.PeekOr()) || m_reader.PeekOr() == 'n')
					{
						// Literal stride; 'n' prefix means negative
						string stride = DemangleNumberAsString();
						paramsStr += "(step=" + stride + ")";
					}
					// else: empty stride means step of 1
				}

				// Optional alignment: 'a' <non-negative-decimal>
				if (m_reader.ConsumeIf('a'))
				{
					while (isdigit(m_reader.PeekOr()))
						(void)m_reader.Read();
				}
			}

			// Consume the '_' separator between parameters and routine name
			if (!m_reader.ConsumeIf('_'))
				throw DemangleException();

			// Remainder is the scalar routine name (maybe a plain C name or a _Z mangled name)
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

			return DemangledTypeNode::NamedType(StringList{routineName + annotation});
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
					if (!m_reader.ConsumeIf('_'))
						throw DemangleException();
				}
				else if (kind == 'v')
				{
					DemangleNumberAsString();
					if (!m_reader.ConsumeIf('_'))
						throw DemangleException();
					DemangleNumberAsString();
					if (!m_reader.ConsumeIf('_'))
						throw DemangleException();
				}
				else
					throw DemangleException();
			};
			consumeCallOffset(); // this-pointer adjustment
			consumeCallOffset(); // return-value adjustment
			oldTopLevel = m_topLevel;
			m_topLevel = false;
			DemangledTypeNode t = DemangleSymbol(name, simplifyTemplates);
			m_topLevel = oldTopLevel;
			return DemangledTypeNode::NamedType(StringList{"covariant_return_thunk_to_" + JoinNameSegments(name) + t.GetStringAfterName(m_platform)});
		}
		case 'C':
		{
			DemangledTypeNode t = DemangleType();
			DemangleNumberAsString();
			if (!m_reader.ConsumeIf('_'))
				throw DemangleException();

			return DemangledTypeNode::NamedType(StringList{"construction_vtable_for_" + DemangleTypeString() + "-in-" + t.GetString()});
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
			if (!m_reader.ConsumeIf('_'))
				throw DemangleException();
			oldTopLevel = m_topLevel;
			m_topLevel = false;
			DemangledTypeNode t = DemangleSymbol(name, simplifyTemplates);
			m_topLevel = oldTopLevel;
			return DemangledTypeNode::NamedType(StringList{"non-virtual_thunk_to_" + JoinNameSegments(name) + t.GetStringAfterName(m_platform)});
		}
		case 'H': // TLS init function
		{
			oldTopLevel = m_topLevel;
			m_topLevel = false;
			DemangledTypeNode t = DemangleSymbol(name, simplifyTemplates);
			m_topLevel = oldTopLevel;
			return DemangledTypeNode::NamedType(StringList{"tls_init_function_for_" + t.GetTypeAndName(name, m_platform)});
		}
		case 'I':
			return DemangledTypeNode::NamedType(StringList{"typeinfo_for_" + DemangleTypeString()});
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
			if (!m_reader.ConsumeIf('_'))
				throw DemangleException();
			DemangleNumberAsString();
			if (!m_reader.ConsumeIf('_'))
				throw DemangleException();
			oldTopLevel = m_topLevel;
			m_topLevel = false;
			DemangledTypeNode t = DemangleSymbol(name, simplifyTemplates);
			m_topLevel = oldTopLevel;
			return DemangledTypeNode::NamedType(StringList{"virtual_thunk_to_" + JoinNameSegments(name) + t.GetStringAfterName(m_platform)});
		}
		case 'V': //Vtable
			return DemangledTypeNode::NamedType(StructNamedTypeClass,
				StringList{"vtable_for_" + DemangleTypeString()});
		case 'W': // TLS wrapper function
		{
			oldTopLevel = m_topLevel;
			m_topLevel = false;
			DemangledTypeNode t = DemangleSymbol(name, simplifyTemplates);
			m_topLevel = oldTopLevel;
			return DemangledTypeNode::NamedType(StringList{"tls_wrapper_function_for_" + t.GetTypeAndName(name, m_platform)});
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

	if (m_reader.ConsumeIf('E'))
	{
		return type;
	}

	cnst = type.IsConst();
	vltl = type.IsVolatile();
	auto suffix = type.GetPointerSuffixBits();
	if (m_reader.ConsumeIf('J'))
	{
		// TODO: If we get here we have a return type. What can we do with this info?
	}
	// Consume any ABI tags on the function/data name (e.g. B5cxx11).
	// For nested names these are already consumed inside DemangleNestedName();
	// this handles the global-scope case.
	while (m_reader.ConsumeIf('B'))
	{
		string savedLastName = m_lastName;
		string abiTag(DemangleSourceName());
		m_lastName = savedLastName;
		ExtendTypeName(type, "[abi:" + abiTag + "]");
	}
	const bool nameRequiresReturnType = m_isParameter || LastTypeNameSegmentHasTemplateArguments(type);
	if (simplifyTemplates)
		DemangledTemplateSimplifier::SimplifyTypeNodeInPlace(type);
	varName = type.RenderTypeNameSegments(m_platform);
	BNNameType nameType = type.GetNameType();
	if (m_isOperatorOverload ||
		nameType == ConstructorNameType ||
		nameType == DestructorNameType ||
		nameType == OperatorDeleteNameType ||
		nameType == OperatorDeleteArrayNameType)
	{
		returnType = DemangledTypeNode::VoidType();
	}
	else if (nameType == OperatorNewNameType || nameType == OperatorNewArrayNameType)
	{
		returnType = DemangledTypeNode::PointerType(DemangledTypeNode::VoidType(), false, false, PointerReferenceType);
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

	m_functionSubstitute.emplace_back();
	while (m_reader.Length() > 0)
	{
		if (m_reader.ConsumeIf('E'))
		{
			break;
		}
		if (m_reader.PeekOr() == '.')
		{
			// Extension, consume the rest
			string ext = m_reader.ReadString(m_reader.Length());

			if (ext == ".eh") ext = "exception handler";
			else if (ext == ".eh_frame") ext = "exception handler frame";
			else if (ext == ".eh_frame_hdr") ext = "exception handler frame header";
			else if (ext == ".debug_frame") ext = "debug frame";

			// On the off chance some invalid mangled string is passed in.
			if (!varName.empty())
				varName.back() += " " + ext;
			break;
		}

		m_isParameter = true;
		LogWithIndentation("Var: %s\n", m_reader.GetRaw());
		if (m_reader.PeekMatch("@@"))
			break;
		DemangledTypeNode param = DemangleType();
		NodeRef paramRef = m_lastTypeRef;
		if (AppendTemplateParamPackExpansion(params, paramRef, true))
			continue;
		if (param.GetClass() == VoidTypeClass)
		{
			if (m_reader.ConsumeIf('E'))
			{
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
			m_reader.ConsumeIf('E');

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
	if (simplifyTemplates)
		DemangledTemplateSimplifier::SimplifyTypeNodeInPlace(type);

	// PrintTables();
	LogWithIndentation("Done: %s%s%s\n", type.GetStringBeforeName(m_platform).c_str(), JoinNameSegments(varName).c_str(),
		type.GetStringAfterName(m_platform).c_str());
	return type;
}


// ===== Non-templated static methods =====

bool DemangleGNU3Static::IsGNU3MangledString(std::string_view name)
{
	string headerless(name);
	string header;
	if (DemangleGlobalHeader(headerless, header))
		return true;

	if (!headerless.compare(0, 2, "_Z") || !headerless.compare(0, 3, "__Z"))
		return true;

	return false;
}


bool DemangleGNU3Static::DemangleGlobalHeader(string& name, string& header)
{
	if (name.empty())
		return false;

	size_t strippedCount = 0;
	string encoded = name;
	while (!encoded.empty() && encoded[0] == '_')
	{
		encoded.erase(0, 1);
		strippedCount ++;
		if (encoded.empty())
			return false;
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
	std::optional<DemanglerResult> DemangleGNU3WithConfig(const DemanglerConfig& config, std::string_view name)
	{
		if (name.empty())
			return std::nullopt;

		Platform& platform = config.GetPlatform();
		bool simplifyTemplates = config.simplifyTemplates;

		// Handle _block_invoke[.N] and _block_invoke_N suffixes (Clang/Apple block invocations).
		// E.g. ____ZN4dyld5_mainEPK12macho_headermiPPKcS5_S5_Pm_block_invoke.110
		//   -> "invocation_function_for_block_in_dyld::_main(...)"
		static constexpr std::string_view blockInvokeSuffix = "_block_invoke";
		size_t blockPos = name.rfind(blockInvokeSuffix);
		if (blockPos != std::string_view::npos)
		{
			// Verify the suffix is _block_invoke optionally followed by [._]<digits> only
			std::string_view tail = name.substr(blockPos + blockInvokeSuffix.size());
			bool validSuffix = tail.empty();
			if (!validSuffix && (tail[0] == '.' || tail[0] == '_'))
			{
				size_t i = 1;
				while (i < tail.size() && isdigit(static_cast<unsigned char>(tail[i])))
					i++;
				validSuffix = (i == tail.size() && i > 1);
			}
			if (validSuffix)
			{
				// Extract the base symbol: everything before _block_invoke
				std::string_view base = name.substr(0, blockPos);
				// Normalize leading underscores: find 'Z' after underscores, keep one '_' before it
				size_t zPos = base.find_first_not_of('_');
				if (zPos != std::string_view::npos && base[zPos] == 'Z')
				{
					string normalized = "_";
					normalized.append(base.substr(zPos));
					if (auto baseResult = DemangleGNU3WithConfig(config, normalized))
					{
						DemanglerResult result;
						result.name = QualifiedName(StringList{
							"invocation_function_for_block_in_" + JoinNameSegments(StringList(baseResult->name.begin(), baseResult->name.end()))});
						result.type = baseResult->type;
						return result;
					}
				}
			}
		}

		// Handle macOS thread-local variable initializer suffix: $tlv$init
		// E.g. __ZL9recursive$tlv$init -> demangle "__ZL9recursive" then annotate.
		static constexpr std::string_view tlvInitSuffix = "$tlv$init";
		if (name.size() > tlvInitSuffix.size() &&
			name.compare(name.size() - tlvInitSuffix.size(), tlvInitSuffix.size(), tlvInitSuffix) == 0)
		{
			std::string_view base = name.substr(0, name.size() - tlvInitSuffix.size());
			if (auto result = DemangleGNU3WithConfig(config, base))
			{
				if (result->name.size() > 0)
					result->name[result->name.size() - 1] += "$tlv$init";
				else
					result->name = QualifiedName(StringList{"$tlv$init"});
				return result;
			}
		}

		string encoding(name);
		string header;
		bool foundHeader = DemangleGNU3Static::DemangleGlobalHeader(encoding, header);

		if (!encoding.compare(0, 2, "_Z"))
			encoding = encoding.substr(2);
		else if (!encoding.compare(0, 3, "__Z"))
			encoding = encoding.substr(3);
		else if (foundHeader && !header.empty())
		{
			DemanglerResult result;
			StringList nameSegments{header, encoding};
			result.name = QualifiedName(nameSegments);
			result.type = DemangledTypeNode::NamedType(nameSegments).Finalize(platform);
			return result;
		}
		else
			return std::nullopt;

		thread_local ::DemangleGNU3 demangle(platform, encoding);
		demangle.Reset(platform, encoding);
		try
		{
			DemanglerResult result;
			StringList nameSegments;
			DemangledTypeNode type = demangle.DemangleSymbol(nameSegments, simplifyTemplates);
			if (simplifyTemplates)
				DemangledTemplateSimplifier::SimplifyTypeNodeInPlace(type);
			result.type = type.Finalize(platform);

			if (nameSegments.empty())
			{
				if (GetFinalizedTypeClass(result.type) == NamedTypeReferenceClass &&
					result.type->GetNamedTypeReference()->GetTypeReferenceClass() == UnknownNamedTypeClass)
				{
					const auto typeName = result.type->GetTypeName();
					nameSegments = StringList(typeName.begin(), typeName.end());
					result.type = nullptr;
				}
				else if (GetFinalizedTypeClass(result.type) == NamedTypeReferenceClass)
				{
					auto typeName = result.type->GetTypeName();
					if (typeName.size() > 0)
						nameSegments = StringList{"_" + typeName[typeName.size() - 1]};
				}
			}

			if (foundHeader && !header.empty())
				nameSegments.insert(nameSegments.begin(), header);
			result.name = QualifiedName(nameSegments);
			return result;
		}
		catch (DemangleException& e)
		{
			LogDebugF("GNU3 demangling failed '{}' '{}'", name, e.what());
		}
		catch (std::exception& e)
		{
			LogDebugF("GNU3 demangling failed '{}' '{}'", name, e.what());
		}
		return std::nullopt;
	}
}


class GNU3Demangler: public Demangler
{
public:
	GNU3Demangler(): Demangler(BN_DEMANGLER_GNU3)
	{
	}
	~GNU3Demangler() override = default;

	bool IsMangledString(const string& name) override
	{
		return DemangleGNU3Static::IsGNU3MangledString(name);
	}

	std::optional<Result> Demangle(const string& name, const Config& config) override
	{
		return DemangleGNU3WithConfig(config, name);
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
		static auto demangler = new GNU3Demangler();
		return Demangler::Register(demangler);
	}
}
