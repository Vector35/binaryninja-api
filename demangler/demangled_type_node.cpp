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

#include "demangled_type_node.h"
#ifdef BINARYNINJACORE_LIBRARY
#include "binaryview.h"
#endif
#include <algorithm>
#include <cassert>
#include <cinttypes>
#include <cstdint>

#ifdef BINARYNINJACORE_LIBRARY
using namespace BinaryNinjaCore;
#define GetClass GetTypeClass
#else
using namespace BinaryNinja;
using namespace std;
#endif

namespace
{
	static constexpr uint8_t DemangledPtr64Bit = 1u << 0;
	static constexpr uint8_t DemangledUnalignedBit = 1u << 1;
	static constexpr uint8_t DemangledRestrictBit = 1u << 2;
	static constexpr uint8_t DemangledReferenceBit = 1u << 3;
	static constexpr uint8_t DemangledLvalueBit = 1u << 4;

	static void AppendPointerSuffixToken(string& out, const char* token)
	{
		if (!out.empty() && out.back() != ' ')
			out += ' ';
		out += token;
	}

	static string JoinNameList(const StringList& name)
	{
		if (name.empty())
			return {};
		if (name.size() == 1)
			return name[0];

		size_t total = (name.size() - 1) * 2;
		for (const auto& segment : name)
			total += segment.size();

		string out;
		out.reserve(total);
		out += name[0];
		for (size_t i = 1; i < name.size(); i++)
		{
			out += "::";
			out += name[i];
		}
		return out;
	}

	static void AppendTemplateArgumentList(string& out, const vector<DemangledTypeNode::Param>& args,
		bool spaceAfterComma, Platform* platform)
	{
		if (args.empty())
			return;

		out += '<';
		for (size_t i = 0; i < args.size(); i++)
		{
			if (i > 0)
				out += spaceAfterComma ? ", " : ",";
			if (args[i].type)
			{
				if (spaceAfterComma)
				{
					string arg;
					args[i].type->AppendString(arg, platform);
					out += arg;
				}
				else
					args[i].type->AppendString(out, platform);
			}
		}
		if (out.back() == '>')
			out += ' ';
		out += '>';
	}

	static DemangledQualifiedName ConvertNameSegments(StringList nameSegments)
	{
		DemangledQualifiedName result;
		result.reserve(nameSegments.size());
		for (auto& segment: nameSegments)
			result.emplace_back(std::move(segment));
		return result;
	}

	static const DemangledQualifiedName& EmptyDemangledQualifiedName()
	{
		static const DemangledQualifiedName empty;
		return empty;
	}

	static size_t ResolveAddressWidth(Platform* platform)
	{
		if (platform)
			return platform->GetAddressSize();
		return 8;
	}

	static size_t ResolveDefaultIntegerWidth(Platform* platform)
	{
		if (platform)
		{
#ifdef BINARYNINJACORE_LIBRARY
			Architecture* platformArch = platform->GetArchitecture();
#else
			Ref<Architecture> platformArch = platform->GetArchitecture();
#endif
			if (platformArch)
				return platformArch->GetDefaultIntegerSize();
		}
		return 4;
	}

	static Ref<CallingConvention> ResolveCallingConvention(BNCallingConventionName cc, Platform* platform)
	{
#ifndef BINARYNINJACORE_LIBRARY
		Ref<Architecture> platformArch;
#endif
		Architecture* arch = nullptr;
		if (platform)
		{
#ifdef BINARYNINJACORE_LIBRARY
			arch = platform->GetArchitecture();
#else
			platformArch = platform->GetArchitecture();
			arch = platformArch.GetPtr();
#endif
		}

		switch (cc)
		{
		case CdeclCallingConvention:
			if (platform)
			{
				auto platformCC = platform->GetCdeclCallingConvention();
				if (platformCC)
					return platformCC;
			}
			if (arch)
			{
				auto archCC = arch->GetCdeclCallingConvention();
				if (archCC)
					return archCC;
			}
			return arch ? arch->GetCallingConventionByName("cdecl") : nullptr;
		case STDCallCallingConvention:
			if (platform)
			{
				auto platformCC = platform->GetStdcallCallingConvention();
				if (platformCC)
					return platformCC;
			}
			if (arch)
			{
				auto archCC = arch->GetStdcallCallingConvention();
				if (archCC)
					return archCC;
			}
			return arch ? arch->GetCallingConventionByName("stdcall") : nullptr;
		case FastcallCallingConvention:
			if (platform)
			{
				auto platformCC = platform->GetFastcallCallingConvention();
				if (platformCC)
					return platformCC;
			}
			if (arch)
			{
				auto archCC = arch->GetFastcallCallingConvention();
				if (archCC)
					return archCC;
			}
			return arch ? arch->GetCallingConventionByName("fastcall") : nullptr;
		case ThisCallCallingConvention:
			if (arch)
				return arch->GetCallingConventionByName("thiscall");
			return nullptr;
		default:
			return nullptr;
		}
	}

}

#define HAS_POINTER_SUFFIX(bit) ((m_pointerSuffixBits & (bit)) != 0)

static const char* CallingConventionString[] =
{
	"",
	"__cdecl",
	"__pascal",
	"__thiscall",
	"__stdcall",
	"__fastcall",
	"__clrcall",
	"__eabi",
	"__vectorcall",
	"__swiftcall",
	"__swiftasync"
};


DemangledNamePart::DemangledNamePart(): m_hasTemplateArgs(false), m_spaceAfterTemplateComma(false)
{
}


DemangledNamePart::DemangledNamePart(string base):
	m_base(std::move(base)), m_hasTemplateArgs(false), m_spaceAfterTemplateComma(false)
{
}


DemangledNamePart::DemangledNamePart(string base, std::shared_ptr<DemangledTypeNode> baseTypeSuffix):
	m_base(std::move(base)), m_baseTypeSuffix(std::move(baseTypeSuffix)), m_hasTemplateArgs(false),
	m_spaceAfterTemplateComma(false)
{
}


DemangledNamePart::DemangledNamePart(
	string base, vector<DemangledTypeNodeParam> templateArgs, bool spaceAfterComma):
	m_base(std::move(base)), m_templateArgs(std::move(templateArgs)), m_hasTemplateArgs(true),
	m_spaceAfterTemplateComma(spaceAfterComma)
{
}


void DemangledNamePart::SetTemplateArguments(vector<DemangledTypeNodeParam> args, bool spaceAfterComma)
{
	m_templateArgs = std::move(args);
	m_hasTemplateArgs = true;
	m_spaceAfterTemplateComma = spaceAfterComma;
}


void DemangledNamePart::AppendString(string& out, Platform* platform) const
{
	out += m_base;
	if (m_baseTypeSuffix)
		m_baseTypeSuffix->AppendString(out, platform);
	if (m_templateArgs.empty() && m_hasTemplateArgs)
	{
		out += "<>";
		return;
	}
	AppendTemplateArgumentList(out, m_templateArgs, m_spaceAfterTemplateComma, platform);
}


string DemangledNamePart::GetString(Platform* platform) const
{
	string out;
	AppendString(out, platform);
	return out;
}


bool DemangledNamePart::IsStructurallyEqual(const DemangledNamePart& other) const
{
	if (m_base != other.m_base || m_hasTemplateArgs != other.m_hasTemplateArgs ||
		m_spaceAfterTemplateComma != other.m_spaceAfterTemplateComma)
		return false;
	if (m_baseTypeSuffix != other.m_baseTypeSuffix)
	{
		if (!m_baseTypeSuffix || !other.m_baseTypeSuffix ||
			!m_baseTypeSuffix->IsStructurallyEqual(*other.m_baseTypeSuffix))
			return false;
	}
	if (m_templateArgs.size() != other.m_templateArgs.size())
		return false;
	for (size_t i = 0; i < m_templateArgs.size(); i++)
	{
		const auto& a = m_templateArgs[i];
		const auto& b = other.m_templateArgs[i];
		if (a.name != b.name)
			return false;
		if (a.type == b.type)
			continue;
		if (!a.type || !b.type || !a.type->IsStructurallyEqual(*b.type))
			return false;
	}
	return true;
}


DemangledNamePart::Ref DemangledNamePart::CreateShared(DemangledNamePart part)
{
	return std::make_shared<DemangledNamePart>(std::move(part));
}


DemangledNamePart::Ref DemangledNamePart::CreateSharedCopy(const DemangledNamePart& part)
{
	return std::make_shared<DemangledNamePart>(part);
}


DemangledTypeNode::DemangledTypeNode()
	: m_nameType(NoNameType), m_pointerSuffixBits(0), m_returnTypeConfidence(BN_FULL_CONFIDENCE),
	  m_const(false), m_volatile(false), m_payload(VoidPayload{})
{
}


DemangledTypeNode::NodeRef DemangledTypeNode::CreateShared(DemangledTypeNode node)
{
	return std::make_shared<DemangledTypeNode>(std::move(node));
}


DemangledTypeNode::NodeRef DemangledTypeNode::CreateSharedCopy(const DemangledTypeNode& node)
{
	return std::make_shared<DemangledTypeNode>(node);
}


DemangledTypeNode DemangledTypeNode::VoidType()
{
	DemangledTypeNode n;
	n.m_payload = VoidPayload{};
	return n;
}


DemangledTypeNode DemangledTypeNode::BoolType()
{
	DemangledTypeNode n;
	n.m_payload = BoolPayload{};
	return n;
}


DemangledTypeNode DemangledTypeNode::IntegerType(size_t width, bool isSigned, const string& altName)
{
	DemangledTypeNode n;
	if (altName == "char16_t" || altName == "char32_t" || altName == "wchar_t")
	{
		n.m_payload = WideCharPayload{width, altName};
		return n;
	}
	IntegerPayload payload;
	payload.width = width;
	payload.isSigned = isSigned;
	if (!(width == 1 && isSigned && altName == "char"))
		payload.altName = altName;
	n.m_payload = std::move(payload);
	return n;
}


DemangledTypeNode DemangledTypeNode::AddressSizedIntegerType(bool isSigned, const string& altName)
{
	DemangledTypeNode n = IntegerType(0, isSigned, altName);
	if (auto payload = std::get_if<IntegerPayload>(&n.m_payload))
		payload->widthKind = AddressWidth;
	return n;
}


DemangledTypeNode DemangledTypeNode::FloatType(size_t width, const string& altName)
{
	DemangledTypeNode n;
	n.m_payload = FloatPayload{width, altName};
	return n;
}


DemangledTypeNode DemangledTypeNode::WideCharType(size_t width, const string& altName)
{
	DemangledTypeNode n;
	n.m_payload = WideCharPayload{width, altName};
	return n;
}


DemangledTypeNode DemangledTypeNode::VarArgsType()
{
	DemangledTypeNode n;
	n.m_payload = VarArgsPayload{};
	return n;
}


DemangledTypeNode DemangledTypeNode::PointerType(DemangledTypeNode child, bool cnst, bool vltl, BNReferenceType refType)
{
	DemangledTypeNode n;
	n.m_const = cnst;
	n.m_volatile = vltl;
	n.m_payload = PointerPayload{CreateShared(std::move(child)), refType};
	return n;
}


DemangledTypeNode DemangledTypeNode::PointerType(NodeRef child, bool cnst, bool vltl, BNReferenceType refType)
{
	DemangledTypeNode n;
	n.m_const = cnst;
	n.m_volatile = vltl;
	n.m_payload = PointerPayload{std::move(child), refType};
	return n;
}


DemangledTypeNode DemangledTypeNode::MemberPointerType(
	DemangledTypeNode child, DemangledQualifiedName ownerName, bool cnst, bool vltl)
{
	DemangledTypeNode n;
	n.m_const = cnst;
	n.m_volatile = vltl;
	n.m_payload = MemberPointerPayload{CreateShared(std::move(child)), std::move(ownerName), false};
	return n;
}


DemangledTypeNode DemangledTypeNode::MemberPointerType(
	NodeRef child, DemangledQualifiedName ownerName, bool cnst, bool vltl)
{
	DemangledTypeNode n;
	n.m_const = cnst;
	n.m_volatile = vltl;
	n.m_payload = MemberPointerPayload{std::move(child), std::move(ownerName), false};
	return n;
}


DemangledTypeNode DemangledTypeNode::ArrayType(DemangledTypeNode child, uint64_t count)
{
	DemangledTypeNode n;
	n.m_payload = ArrayPayload{CreateShared(std::move(child)), count};
	return n;
}


DemangledTypeNode DemangledTypeNode::ArrayType(NodeRef child, uint64_t count)
{
	DemangledTypeNode n;
	n.m_payload = ArrayPayload{std::move(child), count};
	return n;
}


DemangledTypeNode DemangledTypeNode::FunctionType(DemangledTypeNode retType,
	std::nullptr_t, vector<Param> params)
{
	DemangledTypeNode n;
	FunctionPayload payload;
	payload.returnType = CreateShared(std::move(retType));
	payload.params = std::move(params);
	n.m_payload = std::move(payload);
	return n;
}


DemangledTypeNode DemangledTypeNode::FunctionType(NodeRef retType,
	std::nullptr_t, vector<Param> params)
{
	DemangledTypeNode n;
	FunctionPayload payload;
	payload.returnType = std::move(retType);
	payload.params = std::move(params);
	n.m_payload = std::move(payload);
	return n;
}


void DemangledTypeNode::SetImplicitThisParameter(DemangledTypeNode type)
{
	if (auto payload = std::get_if<FunctionPayload>(&m_payload))
	{
		payload->implicitThisParameterType = CreateShared(std::move(type));
		return;
	}
	assert(false && "SetImplicitThisParameter called for non-function demangled type");
}


DemangledTypeNode DemangledTypeNode::NamedType(BNNamedTypeReferenceClass cls,
	StringList nameSegments, size_t width, bool isSigned)
{
	DemangledTypeNode n;
	n.m_payload = NamedTypePayload{cls, ConvertNameSegments(std::move(nameSegments)), width, FixedWidth, isSigned};
	return n;
}

DemangledTypeNode DemangledTypeNode::NamedType(BNNamedTypeReferenceClass cls,
	DemangledQualifiedName nameSegments, size_t width, bool isSigned)
{
	DemangledTypeNode n;
	n.m_payload = NamedTypePayload{cls, std::move(nameSegments), width, FixedWidth, isSigned};
	return n;
}

DemangledTypeNode DemangledTypeNode::NamedTypeWithDefaultIntegerWidth(BNNamedTypeReferenceClass cls,
	StringList nameSegments, bool isSigned)
{
	DemangledTypeNode n = NamedType(cls, std::move(nameSegments), 0, isSigned);
	if (auto payload = std::get_if<NamedTypePayload>(&n.m_payload))
		payload->widthKind = DefaultIntegerWidth;
	return n;
}


DemangledTypeNode DemangledTypeNode::PostfixType(NodeRef child, string suffix)
{
	DemangledTypeNode n;
	n.m_payload = PostfixPayload{std::move(child), std::move(suffix), nullptr};
	return n;
}


DemangledTypeNode DemangledTypeNode::PostfixType(NodeRef child, string separator, NodeRef suffixType)
{
	DemangledTypeNode n = PostfixType(child, std::move(separator));
	if (auto payload = std::get_if<PostfixPayload>(&n.m_payload))
		payload->suffixType = std::move(suffixType);
	return n;
}


uint8_t DemangledTypeNode::PointerSuffixBit(BNPointerSuffix ps)
{
	switch (ps)
	{
	case Ptr64Suffix:
		return DemangledPtr64Bit;
	case UnalignedSuffix:
		return DemangledUnalignedBit;
	case RestrictSuffix:
		return DemangledRestrictBit;
	case ReferenceSuffix:
		return DemangledReferenceBit;
	case LvalueSuffix:
		return DemangledLvalueBit;
	default:
		return 0;
	}
}


size_t DemangledTypeNode::ResolveWidth(size_t width, WidthKind widthKind, Platform* platform)
{
	switch (widthKind)
	{
	case AddressWidth:
		return ResolveAddressWidth(platform);
	case DefaultIntegerWidth:
		return ResolveDefaultIntegerWidth(platform);
	case FixedWidth:
	default:
		return width;
	}
}


BNTypeClass DemangledTypeNode::GetPayloadClass() const
{
	switch (m_payload.index())
	{
	case 0: return VoidTypeClass;
	case 1: return BoolTypeClass;
	case 2: return IntegerTypeClass;
	case 3: return FloatTypeClass;
	case 4: return WideCharTypeClass;
	case 5: return VarArgsTypeClass;
	case 6:
	case 7:
		// PointerPayload and MemberPointerPayload both preserve the public pointer type class.
		return PointerTypeClass;
	case 8: return ArrayTypeClass;
	case 9: return FunctionTypeClass;
	case 10:
	case 11:
		// PostfixPayload is an internal named-type rendering form, so it reports as a named type.
		return NamedTypeReferenceClass;
	default:
		return VoidTypeClass;
	}
}


DemangledTypeNode::NodeRef DemangledTypeNode::GetPrimaryChild() const
{
	if (auto payload = std::get_if<PointerPayload>(&m_payload))
		return payload->childType;
	if (auto payload = std::get_if<MemberPointerPayload>(&m_payload))
		return payload->childType;
	if (auto payload = std::get_if<ArrayPayload>(&m_payload))
		return payload->childType;
	if (auto payload = std::get_if<FunctionPayload>(&m_payload))
		return payload->returnType;
	if (auto payload = std::get_if<PostfixPayload>(&m_payload))
		return payload->childType;
	return nullptr;
}


bool DemangledTypeNode::AddQualifiersToPointerChild(bool cnst, bool vltl)
{
	NodeRef* childType = nullptr;
	if (auto payload = std::get_if<PointerPayload>(&m_payload))
		childType = &payload->childType;
	else if (auto payload = std::get_if<MemberPointerPayload>(&m_payload))
		childType = &payload->childType;
	else
		return false;

	if (!*childType)
		return true;
	if ((*childType).use_count() > 1)
		*childType = CreateSharedCopy(**childType);
	if (cnst)
		(*childType)->SetConst(true);
	if (vltl)
		(*childType)->SetVolatile(true);
	return true;
}


const DemangledQualifiedName& DemangledTypeNode::GetName() const
{
	if (auto payload = std::get_if<NamedTypePayload>(&m_payload))
		return payload->name;
	return EmptyDemangledQualifiedName();
}


DemangledQualifiedName& DemangledTypeNode::GetMutableName()
{
	if (auto payload = std::get_if<NamedTypePayload>(&m_payload))
		return payload->name;
	assert(false && "GetMutableName called for non-named demangled type");
	static thread_local DemangledQualifiedName empty;
	empty.clear();
	return empty;
}


void DemangledTypeNode::SetName(DemangledQualifiedName name)
{
	if (auto payload = std::get_if<NamedTypePayload>(&m_payload))
	{
		payload->name = std::move(name);
		return;
	}
	assert(false && "SetName called for non-named demangled type");
}


BNNamedTypeReferenceClass DemangledTypeNode::GetNTRClass() const
{
	if (auto payload = std::get_if<NamedTypePayload>(&m_payload))
		return payload->ntrClass;
	return UnknownNamedTypeClass;
}


void DemangledTypeNode::SetNTRType(BNNamedTypeReferenceClass cls)
{
	if (auto payload = std::get_if<NamedTypePayload>(&m_payload))
	{
		payload->ntrClass = cls;
		return;
	}
	assert(false && "SetNTRType called for non-named demangled type");
}


void DemangledTypeNode::SetParenthesizedMemberPointer(bool parenthesized)
{
	if (auto payload = std::get_if<MemberPointerPayload>(&m_payload))
	{
		payload->parenthesized = parenthesized;
		return;
	}
	assert(false && "SetParenthesizedMemberPointer called for non-member-pointer demangled type");
}


void DemangledTypeNode::SetCallingConventionName(BNCallingConventionName cc)
{
	if (auto payload = std::get_if<FunctionPayload>(&m_payload))
	{
		payload->callingConventionName = cc;
		return;
	}
	assert(false && "SetCallingConventionName called for non-function demangled type");
}


bool DemangledTypeNode::HasTemplateArguments() const
{
	const auto* payload = std::get_if<NamedTypePayload>(&m_payload);
	if (!payload)
		return false;
	for (const auto& segment: payload->name)
		if (segment.HasTemplateArguments())
			return true;
	return false;
}


bool DemangledTypeNode::IsStructurallyEqual(const DemangledTypeNode& other) const
{
	if (m_nameType != other.m_nameType || m_pointerSuffixBits != other.m_pointerSuffixBits ||
		m_returnTypeConfidence != other.m_returnTypeConfidence ||
		m_const != other.m_const || m_volatile != other.m_volatile ||
		m_payload.index() != other.m_payload.index())
		return false;

	auto typePtrsEqual = [](const NodeRef& a, const NodeRef& b) {
		if (a == b)
			return true;
		if (!a || !b)
			return false;
		return a->IsStructurallyEqual(*b);
	};

	auto namePartsEqual = [](const DemangledQualifiedName& a, const DemangledQualifiedName& b) {
		if (a.size() != b.size())
			return false;
		for (size_t i = 0; i < a.size(); i++)
		{
			if (!a[i].IsStructurallyEqual(b[i]))
				return false;
		}
		return true;
	};

	auto paramsEqual = [&typePtrsEqual](const vector<Param>& a, const vector<Param>& b) {
		if (a.size() != b.size())
			return false;
		for (size_t i = 0; i < a.size(); i++)
		{
			if (a[i].name != b[i].name || !typePtrsEqual(a[i].type, b[i].type))
				return false;
		}
		return true;
	};

	if (auto payload = std::get_if<VoidPayload>(&m_payload))
		return payload && std::get_if<VoidPayload>(&other.m_payload);
	if (auto payload = std::get_if<BoolPayload>(&m_payload))
		return payload && std::get_if<BoolPayload>(&other.m_payload);
	if (auto payload = std::get_if<VarArgsPayload>(&m_payload))
		return payload && std::get_if<VarArgsPayload>(&other.m_payload);
	if (auto payload = std::get_if<IntegerPayload>(&m_payload))
	{
		auto otherPayload = std::get_if<IntegerPayload>(&other.m_payload);
		return otherPayload && payload->width == otherPayload->width &&
			payload->widthKind == otherPayload->widthKind &&
			payload->isSigned == otherPayload->isSigned && payload->altName == otherPayload->altName;
	}
	if (auto payload = std::get_if<FloatPayload>(&m_payload))
	{
		auto otherPayload = std::get_if<FloatPayload>(&other.m_payload);
		return otherPayload && payload->width == otherPayload->width && payload->altName == otherPayload->altName;
	}
	if (auto payload = std::get_if<WideCharPayload>(&m_payload))
	{
		auto otherPayload = std::get_if<WideCharPayload>(&other.m_payload);
		return otherPayload && payload->width == otherPayload->width && payload->altName == otherPayload->altName;
	}
	if (auto payload = std::get_if<PointerPayload>(&m_payload))
	{
		auto otherPayload = std::get_if<PointerPayload>(&other.m_payload);
		return otherPayload && payload->referenceType == otherPayload->referenceType &&
			typePtrsEqual(payload->childType, otherPayload->childType);
	}
	if (auto payload = std::get_if<MemberPointerPayload>(&m_payload))
	{
		auto otherPayload = std::get_if<MemberPointerPayload>(&other.m_payload);
		return otherPayload && payload->parenthesized == otherPayload->parenthesized &&
			typePtrsEqual(payload->childType, otherPayload->childType) &&
			namePartsEqual(payload->ownerName, otherPayload->ownerName);
	}
	if (auto payload = std::get_if<ArrayPayload>(&m_payload))
	{
		auto otherPayload = std::get_if<ArrayPayload>(&other.m_payload);
		return otherPayload && payload->elements == otherPayload->elements &&
			typePtrsEqual(payload->childType, otherPayload->childType);
	}
	if (auto payload = std::get_if<FunctionPayload>(&m_payload))
	{
		auto otherPayload = std::get_if<FunctionPayload>(&other.m_payload);
		return otherPayload && payload->callingConventionName == otherPayload->callingConventionName &&
			typePtrsEqual(payload->returnType, otherPayload->returnType) &&
			typePtrsEqual(payload->implicitThisParameterType, otherPayload->implicitThisParameterType) &&
			paramsEqual(payload->params, otherPayload->params);
	}
	if (auto payload = std::get_if<NamedTypePayload>(&m_payload))
	{
		auto otherPayload = std::get_if<NamedTypePayload>(&other.m_payload);
		return otherPayload && payload->ntrClass == otherPayload->ntrClass &&
			payload->width == otherPayload->width && payload->widthKind == otherPayload->widthKind &&
			payload->isSigned == otherPayload->isSigned &&
			namePartsEqual(payload->name, otherPayload->name);
	}
	if (auto payload = std::get_if<PostfixPayload>(&m_payload))
	{
		auto otherPayload = std::get_if<PostfixPayload>(&other.m_payload);
		return otherPayload && payload->suffix == otherPayload->suffix &&
			typePtrsEqual(payload->childType, otherPayload->childType) &&
			typePtrsEqual(payload->suffixType, otherPayload->suffixType);
	}

	return false;
}


StringList DemangledTypeNode::RenderTypeNameSegments(Platform* platform) const
{
	StringList result;
	if (auto payload = std::get_if<PostfixPayload>(&m_payload))
	{
		result.push_back(GetString(platform));
		return result;
	}
	auto payload = std::get_if<NamedTypePayload>(&m_payload);
	if (!payload)
		return result;
	result.reserve(payload->name.size());
	for (const auto& segment: payload->name)
		result.push_back(segment.GetString(platform));
	return result;
}


void DemangledTypeNode::AddPointerSuffixes(TypeBuilder& tb, bool omitPtr64) const
{
	if (HAS_POINTER_SUFFIX(DemangledPtr64Bit) && !omitPtr64)
		tb.AddPointerSuffix(Ptr64Suffix);
	if (HAS_POINTER_SUFFIX(DemangledUnalignedBit))
		tb.AddPointerSuffix(UnalignedSuffix);
	if (HAS_POINTER_SUFFIX(DemangledRestrictBit))
		tb.AddPointerSuffix(RestrictSuffix);
	if (HAS_POINTER_SUFFIX(DemangledReferenceBit))
		tb.AddPointerSuffix(ReferenceSuffix);
	if (HAS_POINTER_SUFFIX(DemangledLvalueBit))
		tb.AddPointerSuffix(LvalueSuffix);
}


bool DemangledTypeNode::HasPostfixType() const
{
	return std::holds_alternative<PostfixPayload>(m_payload);
}


void DemangledTypeNode::AppendPostfixType(string& out, Platform* platform) const
{
	const auto* payload = std::get_if<PostfixPayload>(&m_payload);
	if (!payload)
		return;
	if (payload->childType)
		payload->childType->AppendString(out, platform);
	out += payload->suffix;
	if (payload->suffixType)
		payload->suffixType->AppendString(out, platform);
}


void DemangledTypeNode::AppendModifiers(string& out) const
{
	if (m_const && m_volatile)
		out += " const volatile";
	else if (m_const)
		out += " const";
	else if (m_volatile)
		out += " volatile";
}


void DemangledTypeNode::AppendPointerSuffix(string& out) const
{
	if (HAS_POINTER_SUFFIX(DemangledUnalignedBit))
		AppendPointerSuffixToken(out, "__unaligned");
	if (HAS_POINTER_SUFFIX(DemangledRestrictBit))
		AppendPointerSuffixToken(out, "__restrict");
	if (HAS_POINTER_SUFFIX(DemangledReferenceBit))
		AppendPointerSuffixToken(out, "&");
	if (HAS_POINTER_SUFFIX(DemangledLvalueBit))
		AppendPointerSuffixToken(out, "&&");
}


void DemangledTypeNode::AppendNamePartList(
	string& out, const DemangledQualifiedName& name, Platform* platform)
{
	if (name.empty())
		return;
	name[0].AppendString(out, platform);
	for (size_t i = 1; i < name.size(); i++)
	{
		out += "::";
		name[i].AppendString(out, platform);
	}
}


void DemangledTypeNode::AppendTypeName(string& out, Platform* platform) const
{
	if (auto payload = std::get_if<NamedTypePayload>(&m_payload))
		AppendNamePartList(out, payload->name, platform);
}


string DemangledTypeNode::GetStringBeforeName(Platform* platform) const
{
	string out;
	AppendBeforeName(out, nullptr, platform);
	return out;
}


string DemangledTypeNode::GetStringAfterName(Platform* platform) const
{
	string out;
	AppendAfterName(out, nullptr, platform);
	return out;
}


void DemangledTypeNode::AppendBeforeName(string& out, const DemangledTypeNode* parentType, Platform* platform) const
{
	switch (GetPayloadClass())
	{
	case FunctionTypeClass:
	{
		const auto& payload = std::get<FunctionPayload>(m_payload);
		// Return type before name
		if (payload.returnType)
		{
			if (!out.empty() && out.back() != ' ' && out.back() != '(')
				out += ' ';
			payload.returnType->AppendBeforeName(out, this, platform);
		}
		// If parent is a pointer, add "(" for function pointer syntax
		if (parentType && parentType->GetPayloadClass() == PointerTypeClass)
		{
			const auto* parentMemberPointer = std::get_if<MemberPointerPayload>(&parentType->m_payload);
			if (!out.empty() && out.back() != ' ' &&
				!(parentMemberPointer && parentMemberPointer->parenthesized))
				out += ' ';
			out += '(';
		}
		if (static_cast<size_t>(payload.callingConventionName) < (sizeof(CallingConventionString) / sizeof(CallingConventionString[0])))
		{
			const char* callingConvention = CallingConventionString[static_cast<size_t>(payload.callingConventionName)];
			if (callingConvention[0] != 0)
			{
				if (!out.empty() && out.back() != ' ' && out.back() != '(')
					out += ' ';
				out += callingConvention;
			}
		}
		break;
	}

	case IntegerTypeClass:
	{
		const auto& payload = std::get<IntegerPayload>(m_payload);
		const size_t width = ResolveWidth(payload.width, payload.widthKind, platform);
		if (!payload.altName.empty())
			out += payload.altName;
		else if (payload.isSigned && width == 1)
			out += "char";
		else if (payload.isSigned)
		{
			out += "int";
			out += to_string(width * 8);
			out += "_t";
		}
		else
		{
			out += "uint";
			out += to_string(width * 8);
			out += "_t";
		}
		AppendModifiers(out);
		break;
	}

	case FloatTypeClass:
	{
		const auto& payload = std::get<FloatPayload>(m_payload);
		if (!payload.altName.empty())
			out += payload.altName;
		else switch (payload.width)
		{
		case 2: out += "float16"; break;
		case 4: out += "float"; break;
		case 8: out += "double"; break;
		case 10: out += "long double"; break;
		default:
			out += "float";
			out += to_string(payload.width * 8);
			break;
		}
		AppendModifiers(out);
		break;
	}

	case BoolTypeClass:
		out += "bool";
		AppendModifiers(out);
		break;

	case VoidTypeClass:
		out += "void";
		AppendModifiers(out);
		break;

	case VarArgsTypeClass:
		out += "...";
		break;

	case PointerTypeClass:
		if (auto payload = std::get_if<MemberPointerPayload>(&m_payload))
		{
			if (payload->childType)
				payload->childType->AppendBeforeName(out, this, platform);
			if (payload->parenthesized)
			{
				if (out.empty() || out.back() != '(')
					out += '(';
			}
			else if (!out.empty() && out.back() != ' ' && out.back() != '(')
				out += ' ';
			if (!payload->ownerName.empty())
				AppendNamePartList(out, payload->ownerName, platform);
			out += "::*";
		}
		else if (auto payload = std::get_if<PointerPayload>(&m_payload))
		{
			if (payload->childType)
				payload->childType->AppendBeforeName(out, this, platform);
			switch (payload->referenceType)
			{
			case ReferenceReferenceType: out += '&'; break;
			case PointerReferenceType:   out += '*'; break;
			case RValueReferenceType:    out += "&&"; break;
			default: break;
			}
		}
		if ((m_pointerSuffixBits & (DemangledUnalignedBit | DemangledRestrictBit |
			DemangledReferenceBit | DemangledLvalueBit)) != 0)
		{
			out += ' ';
			AppendPointerSuffix(out);
		}
		AppendModifiers(out);
		break;

	case ArrayTypeClass:
	{
		const auto& payload = std::get<ArrayPayload>(m_payload);
		if (payload.childType)
			payload.childType->AppendBeforeName(out, this, platform);
		if (parentType && parentType->GetPayloadClass() == PointerTypeClass)
		{
			const auto* parentMemberPointer = std::get_if<MemberPointerPayload>(&parentType->m_payload);
			out += (parentMemberPointer && parentMemberPointer->parenthesized) ? "(" : " (";
		}
		break;
	}

	case NamedTypeReferenceClass:
		if (HasPostfixType())
		{
			AppendPostfixType(out, platform);
			AppendModifiers(out);
			break;
		}
	{
		const auto& payload = std::get<NamedTypePayload>(m_payload);
		switch (payload.ntrClass)
		{
		case ClassNamedTypeClass:  out += "class "; break;
		case StructNamedTypeClass: out += "struct "; break;
		case UnionNamedTypeClass:  out += "union "; break;
		case EnumNamedTypeClass:   out += "enum "; break;
		default: break;
		}
		AppendTypeName(out, platform);
		AppendModifiers(out);
		break;
	}

	case WideCharTypeClass:
	{
		const auto& payload = std::get<WideCharPayload>(m_payload);
		if (!payload.altName.empty())
			out += payload.altName;
		else
			out += "wchar_t";
		AppendModifiers(out);
		break;
	}

	default:
		break;
	}
}


static string FormatArrayCount(uint64_t elements)
{
	return string(fmt::format("{:#x}", elements));
}


void DemangledTypeNode::AppendAfterName(string& out, const DemangledTypeNode* parentType, Platform* platform) const
{
	switch (GetPayloadClass())
	{
	case FunctionTypeClass:
	{
		const auto& payload = std::get<FunctionPayload>(m_payload);
		// Close the "(" from before-name if parent is pointer
		if (parentType && parentType->GetPayloadClass() == PointerTypeClass)
			out += ')';

		out += '(';
		for (size_t i = 0; i < payload.params.size(); i++)
		{
			if (i != 0)
				out += ", ";
			if (payload.params[i].type)
				payload.params[i].type->AppendString(out, platform);
		}
		out += ')';
		AppendModifiers(out);
		if ((m_pointerSuffixBits & (DemangledUnalignedBit | DemangledRestrictBit |
			DemangledReferenceBit | DemangledLvalueBit)) != 0)
			AppendPointerSuffix(out);
		// Return type's after-name tokens
		if (payload.returnType)
			payload.returnType->AppendAfterName(out, this, platform);
		break;
	}
	case PointerTypeClass:
		if (auto payload = std::get_if<MemberPointerPayload>(&m_payload))
		{
			if (payload->childType)
				payload->childType->AppendAfterName(out, this, platform);
			const BNTypeClass childClass = payload->childType ? payload->childType->GetPayloadClass() : VoidTypeClass;
			if (payload->parenthesized && (!payload->childType ||
				(childClass != FunctionTypeClass && childClass != ArrayTypeClass)))
				out += ')';
		}
		else if (auto payload = std::get_if<PointerPayload>(&m_payload))
		{
			if (payload->childType)
				payload->childType->AppendAfterName(out, this, platform);
		}
		break;
	case ArrayTypeClass:
	{
		const auto& payload = std::get<ArrayPayload>(m_payload);
		if (parentType && parentType->GetPayloadClass() == PointerTypeClass)
			out += ")";
		out += "[" + FormatArrayCount(payload.elements) + "]";
		if (payload.childType)
			payload.childType->AppendAfterName(out, this, platform);
		break;
	}
	default:
		break;
	}
}


void DemangledTypeNode::AppendString(string& out, Platform* platform) const
{
	size_t beforeEnd = out.size();
	AppendBeforeName(out, nullptr, platform);
	beforeEnd = out.size(); // track where "before" ends

	string after;
	AppendAfterName(after, nullptr, platform);

	if (!after.empty() && beforeEnd > 0)
	{
		char lastBefore = out[beforeEnd - 1];
		NodeRef child = GetPrimaryChild();
		if (lastBefore != ' ' && lastBefore != '*' && lastBefore != '&'
			&& after.front() != ' ' && after.front() != '['
			&& child && child->GetPayloadClass() != FunctionTypeClass)
		{
			out += ' ';
		}
	}
	out += after;
}


string DemangledTypeNode::GetString() const
{
	return GetString(nullptr);
}


string DemangledTypeNode::GetString(Platform* platform) const
{
	string out;
	AppendString(out, platform);
	return out;
}


string DemangledTypeNode::GetTypeAndName(const StringList& name) const
{
	return GetTypeAndName(name, nullptr);
}


string DemangledTypeNode::GetTypeAndName(const StringList& name, Platform* platform) const
{
	const string before = GetStringBeforeName(platform);
	const string qName = JoinNameList(name);
	const string after = GetStringAfterName(platform);
	if ((!before.empty() && !qName.empty() && before.back() != ' ' && qName.front() != ' ')
		|| (!before.empty() && !after.empty() && before.back() != ' ' && after.front() != ' '))
		return before + " " + qName + after;
	return before + qName + after;
}


bool DemangledTypeNode::HasUndeterminedTopLevelSize() const
{
	if (auto payload = std::get_if<NamedTypePayload>(&m_payload))
		return payload->widthKind == FixedWidth && payload->width == 0;
	if (std::holds_alternative<PostfixPayload>(m_payload))
		return true;
	if (auto payload = std::get_if<ArrayPayload>(&m_payload))
		return payload->childType && payload->childType->HasUndeterminedTopLevelSize();
	return false;
}


uint8_t DemangledTypeNode::GetValueConfidence() const
{
	return HasUndeterminedTopLevelSize() ? BN_DEFAULT_CONFIDENCE : BN_FULL_CONFIDENCE;
}


Ref<Type> DemangledTypeNode::Finalize(Platform* platform) const
{
	switch (GetPayloadClass())
	{
	case VoidTypeClass:
	{
		if (!m_const && !m_volatile)
			return Type::VoidType();
		TypeBuilder tb = TypeBuilder::VoidType();
		tb.SetConst(m_const);
		tb.SetVolatile(m_volatile);
		return tb.Finalize();
	}

	case BoolTypeClass:
	{
		if (!m_const && !m_volatile)
			return Type::BoolType();
		TypeBuilder tb = TypeBuilder::BoolType();
		tb.SetConst(m_const);
		tb.SetVolatile(m_volatile);
		return tb.Finalize();
	}

	case IntegerTypeClass:
	{
		const auto& payload = std::get<IntegerPayload>(m_payload);
		const size_t width = ResolveWidth(payload.width, payload.widthKind, platform);
		if (!m_const && !m_volatile)
			return Type::IntegerType(width, payload.isSigned, payload.altName);
		TypeBuilder tb = TypeBuilder::IntegerType(width, payload.isSigned, payload.altName);
		tb.SetConst(m_const);
		tb.SetVolatile(m_volatile);
		return tb.Finalize();
	}

	case FloatTypeClass:
	{
		const auto& payload = std::get<FloatPayload>(m_payload);
		if (!m_const && !m_volatile)
			return Type::FloatType(payload.width, payload.altName);
		TypeBuilder tb = TypeBuilder::FloatType(payload.width, payload.altName);
		tb.SetConst(m_const);
		tb.SetVolatile(m_volatile);
		return tb.Finalize();
	}

	case VarArgsTypeClass:
		return TypeBuilder::VarArgsType().Finalize();

	case WideCharTypeClass:
	{
		const auto& payload = std::get<WideCharPayload>(m_payload);
		if (!m_const && !m_volatile)
			return Type::WideCharType(payload.width, payload.altName);
		TypeBuilder tb = TypeBuilder::WideCharType(payload.width, payload.altName);
		tb.SetConst(m_const);
		tb.SetVolatile(m_volatile);
		return tb.Finalize();
	}

	case PointerTypeClass:
	{
		if (auto payload = std::get_if<MemberPointerPayload>(&m_payload))
		{
			Ref<Type> child = payload->childType ? payload->childType->Finalize(platform) : Ref<Type>(Type::VoidType());
			TypeBuilder tb = TypeBuilder::PointerType(
				ResolveWidth(0, AddressWidth, platform), child, m_const, m_volatile, PointerReferenceType);
			AddPointerSuffixes(tb, true);
			Ref<Type> normalized = tb.Finalize();
			return Type::NamedType(QualifiedName({GetString(platform)}), normalized.GetPtr());
		}

		const auto& payload = std::get<PointerPayload>(m_payload);
		Ref<Type> child = payload.childType ? payload.childType->Finalize(platform) : Ref<Type>(Type::VoidType());
		TypeBuilder tb = TypeBuilder::PointerType(
			ResolveWidth(0, AddressWidth, platform), child, m_const, m_volatile, payload.referenceType);
		AddPointerSuffixes(tb, true);
		Ref<Type> normalized = tb.Finalize();
		return normalized;
	}

	case ArrayTypeClass:
	{
		const auto& payload = std::get<ArrayPayload>(m_payload);
		Ref<Type> child = payload.childType ? payload.childType->Finalize(platform) : Ref<Type>(Type::VoidType());
		TypeBuilder tb = TypeBuilder::ArrayType(child, payload.elements);
		if (m_const)
			tb.SetConst(m_const);
		if (m_volatile)
			tb.SetVolatile(m_volatile);
		return tb.Finalize();
	}

	case FunctionTypeClass:
	{
		const auto& payload = std::get<FunctionPayload>(m_payload);
		Ref<Type> retType = payload.returnType ? payload.returnType->Finalize(platform) : Ref<Type>(Type::VoidType());
		uint8_t retTypeConfidence = payload.returnType ? payload.returnType->GetValueConfidence() : BN_FULL_CONFIDENCE;
		retTypeConfidence = std::min(retTypeConfidence, m_returnTypeConfidence);

		vector<FunctionParameter> finalParams;
		finalParams.reserve(payload.params.size() + (payload.implicitThisParameterType ? 1 : 0));
		if (payload.implicitThisParameterType)
		{
			Ref<Type> thisType = payload.implicitThisParameterType->Finalize(platform);
			finalParams.push_back({"this", thisType->WithConfidence(payload.implicitThisParameterType->GetValueConfidence()),
				DefaultLocationSource, Variable()});
		}
		for (auto& p : payload.params)
		{
			Ref<Type> pType = p.type ? p.type->Finalize(platform) : Ref<Type>(Type::VoidType());
			uint8_t pTypeConfidence = p.type ? p.type->GetValueConfidence() : BN_FULL_CONFIDENCE;
			finalParams.push_back({p.name, pType->WithConfidence(pTypeConfidence), DefaultLocationSource, Variable()});
		}
		Confidence<Ref<CallingConvention>> callingConvention;
		if (payload.callingConventionName != NoCallingConvention)
		{
			if (auto resolvedCallingConvention = ResolveCallingConvention(payload.callingConventionName, platform))
				callingConvention = Confidence<Ref<CallingConvention>>(resolvedCallingConvention, BN_FULL_CONFIDENCE);
		}
		TypeBuilder tb = TypeBuilder::FunctionType(
			retType->WithConfidence(retTypeConfidence), callingConvention, finalParams,
			Confidence<bool>(false, 0));
		tb.SetConst(m_const);
		tb.SetVolatile(m_volatile);
		AddPointerSuffixes(tb);
		tb.SetNameType(m_nameType);
		if (payload.callingConventionName != NoCallingConvention)
			tb.SetCallingConventionName(payload.callingConventionName);
		return tb.Finalize();
	}

	case NamedTypeReferenceClass:
	{
		if (auto payload = std::get_if<PostfixPayload>(&m_payload))
		{
			QualifiedName name(RenderTypeNameSegments(platform));
			TypeBuilder tb = TypeBuilder::NamedType(
				NamedTypeReference::GenerateAutoDemangledTypeReference(UnknownNamedTypeClass, name), 0, 1);
			tb.SetConst(m_const);
			tb.SetVolatile(m_volatile);
			AddPointerSuffixes(tb);
			tb.SetNameType(m_nameType);
			tb.SetHasTemplateArguments(false);
			return tb.Finalize();
		}

		const auto& payload = std::get<NamedTypePayload>(m_payload);
		QualifiedName name(RenderTypeNameSegments(platform));
		TypeBuilder tb = TypeBuilder::NamedType(
			NamedTypeReference::GenerateAutoDemangledTypeReference(payload.ntrClass, name),
			ResolveWidth(payload.width, payload.widthKind, platform), 1);
		tb.SetConst(m_const);
		tb.SetVolatile(m_volatile);
		AddPointerSuffixes(tb);
		tb.SetNameType(m_nameType);
		tb.SetHasTemplateArguments(HasTemplateArguments());
		return tb.Finalize();
	}

	default:
		return Type::VoidType();
	}
}

#undef HAS_POINTER_SUFFIX
#undef GetClass
