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
#include "base/assertions.h"
#include <algorithm>
#include <fmt/format.h>
#include <unordered_set>

#ifdef BINARYNINJACORE_LIBRARY
using namespace BinaryNinjaCore;
#define GetClass GetTypeClass
#else
using namespace BinaryNinja;
using namespace std;
#endif

namespace
{
	constexpr uint8_t DemangledPtr64Bit = 1u << 0;
	constexpr uint8_t DemangledUnalignedBit = 1u << 1;
	constexpr uint8_t DemangledRestrictBit = 1u << 2;
	constexpr uint8_t DemangledReferenceBit = 1u << 3;
	constexpr uint8_t DemangledLvalueBit = 1u << 4;

	class DemanglerFallbackArchitecture : public Architecture
	{
	public:
		DemanglerFallbackArchitecture() : Architecture("demangler_fallback") {}

		BNEndianness GetEndianness() const override { return LittleEndian; }
		size_t GetAddressSize() const override { return 8; }
		size_t GetDefaultIntegerSize() const override { return 4; }
		size_t GetInstructionAlignment() const override { return 1; }
		size_t GetMaxInstructionLength() const override { return 1; }
		size_t GetOpcodeDisplayLength() const override { return 1; }

#ifdef BINARYNINJACORE_LIBRARY
		bool GetInstructionInfo(const uint8_t*, uint64_t, size_t, InstructionInfo&) override { return false; }
		bool GetInstructionText(const uint8_t*, uint64_t, size_t&, vector<InstructionTextToken>&) override { return false; }
		bool GetInstructionTextWithContext(const uint8_t*, uint64_t, size_t&, void*, vector<InstructionTextToken>&) override { return false; }
		bool GetInstructionLowLevelIL(const uint8_t*, uint64_t, size_t&, LowLevelILFunction&) override { return false; }
		void AnalyzeBasicBlocks(Function&, BNBasicBlockAnalysisContext*) override {}
		bool LiftFunction(LowLevelILFunction&, BNFunctionLifterContext*) override { return false; }
		void FreeFunctionArchContext(void*) override {}
		string GetRegisterName(uint32_t) override { return {}; }
		string GetFlagName(uint32_t) override { return {}; }
		string GetFlagWriteTypeName(uint32_t) override { return {}; }
		string GetSemanticFlagClassName(uint32_t) override { return {}; }
		string GetSemanticFlagGroupName(uint32_t) override { return {}; }
		vector<uint32_t> GetFullWidthRegisters() override { return {}; }
		vector<uint32_t> GetAllRegisters() override { return {}; }
		vector<uint32_t> GetAllFlags() override { return {}; }
		vector<uint32_t> GetAllFlagWriteTypes() override { return {}; }
		vector<uint32_t> GetAllSemanticFlagClasses() override { return {}; }
		vector<uint32_t> GetAllSemanticFlagGroups() override { return {}; }
		BNFlagRole GetFlagRole(uint32_t, uint32_t = 0) override { return SpecialFlagRole; }
		vector<uint32_t> GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition, uint32_t = 0) override { return {}; }
		vector<uint32_t> GetFlagsRequiredForSemanticFlagGroup(uint32_t) override { return {}; }
		map<uint32_t, BNLowLevelILFlagCondition> GetFlagConditionsForSemanticFlagGroup(uint32_t) override { return {}; }
		uint32_t GetSemanticClassForFlagWriteType(uint32_t) override { return 0; }
		BNRegisterInfo GetRegisterInfo(uint32_t) override { return {}; }
		uint32_t GetStackPointerRegister() override { return 0; }
		BNIntrinsicClass GetIntrinsicClass(uint32_t) override { return GeneralIntrinsicClass; }
		string GetIntrinsicName(uint32_t) override { return {}; }
		vector<uint32_t> GetAllIntrinsics() override { return {}; }
		vector<NameAndType> GetIntrinsicInputs(uint32_t) override { return {}; }
		vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t) override { return {}; }
		bool CanAssemble() override { return false; }
		bool Assemble(const string&, uint64_t, DataBuffer&, string&) override { return false; }
		bool IsNeverBranchPatchAvailable(const uint8_t*, uint64_t, size_t) override { return false; }
		bool IsAlwaysBranchPatchAvailable(const uint8_t*, uint64_t, size_t) override { return false; }
		bool IsInvertBranchPatchAvailable(const uint8_t*, uint64_t, size_t) override { return false; }
		bool IsSkipAndReturnZeroPatchAvailable(const uint8_t*, uint64_t, size_t) override { return false; }
		bool IsSkipAndReturnValuePatchAvailable(const uint8_t*, uint64_t, size_t) override { return false; }
		bool ConvertToNop(uint8_t*, uint64_t, size_t) override { return false; }
		bool AlwaysBranch(uint8_t*, uint64_t, size_t) override { return false; }
		bool InvertBranch(uint8_t*, uint64_t, size_t) override { return false; }
		bool SkipAndReturnValue(uint8_t*, uint64_t, size_t, uint64_t) override { return false; }
		Architecture* RegisterArchitectureHook(BNCustomArchitecture*) override { return nullptr; }
#else
		bool GetInstructionInfo(const uint8_t*, uint64_t, size_t, InstructionInfo&) override { return false; }
		bool GetInstructionText(const uint8_t*, uint64_t, size_t&, vector<InstructionTextToken>&) override { return false; }
		bool GetInstructionLowLevelIL(const uint8_t*, uint64_t, size_t&, LowLevelILFunction&) override { return false; }
#endif
	};

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
		bool spaceAfterComma, Platform& platform)
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

	static size_t ResolveAddressWidth(const Platform& platform)
	{
		return platform.GetAddressSize();
	}

	static size_t ResolveDefaultIntegerWidth(const Platform& platform)
	{
		auto platformArch = platform.GetArchitecture();
		return platformArch->GetDefaultIntegerSize();
	}

	static Ref<CallingConvention> ResolveCallingConvention(BNCallingConventionName cc, const Platform& platform)
	{
		auto platformArch = platform.GetArchitecture();
		Architecture* arch = platformArch;

		switch (cc)
		{
		case CdeclCallingConvention:
			if (auto platformCC = platform.GetCdeclCallingConvention())
				return platformCC;
			if (auto archCC = arch->GetCdeclCallingConvention())
				return archCC;
			return arch->GetCallingConventionByName("cdecl");
		case STDCallCallingConvention:
			if (auto platformCC = platform.GetStdcallCallingConvention())
				return platformCC;
			if (auto archCC = arch->GetStdcallCallingConvention())
				return archCC;
			return arch->GetCallingConventionByName("stdcall");
		case FastcallCallingConvention:
			if (auto platformCC = platform.GetFastcallCallingConvention())
				return platformCC;
			if (auto archCC = arch->GetFastcallCallingConvention())
				return archCC;
			return arch->GetCallingConventionByName("fastcall");
		case ThisCallCallingConvention:
			return arch->GetCallingConventionByName("thiscall");
		default:
			return nullptr;
		}
	}

}

Platform& GetDemanglerFallbackPlatform()
{
	static DemanglerFallbackArchitecture arch;
	static auto platform = arch.GetStandalonePlatform();
	return *platform;
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


DemangledNamePart::DemangledNamePart(const char* base):
	m_base(base), m_hasTemplateArgs(false), m_spaceAfterTemplateComma(false)
{
}


DemangledNamePart::DemangledNamePart(std::string_view base):
	m_base(base), m_hasTemplateArgs(false), m_spaceAfterTemplateComma(false)
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


void DemangledNamePart::ClearTemplateArguments()
{
	m_templateArgs.clear();
	m_hasTemplateArgs = false;
	m_spaceAfterTemplateComma = false;
}


void DemangledNamePart::AppendString(string& out, Platform& platform) const
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


string DemangledNamePart::GetString(Platform& platform) const
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
	BN_ASSERT(false && "SetImplicitThisParameter called for non-function demangled type");
}


DemangledTypeNode DemangledTypeNode::NamedType(BNNamedTypeReferenceClass cls,
	StringList nameSegments, size_t width, bool isSigned)
{
	DemangledTypeNode n;
	n.m_payload = NamedTypePayload{cls, ConvertNameSegments(std::move(nameSegments)), width, FixedWidth, isSigned};
	return n;
}

DemangledTypeNode DemangledTypeNode::NamedType(BNNamedTypeReferenceClass cls,
	std::string_view nameSegment, size_t width, bool isSigned)
{
	DemangledQualifiedName nameSegments;
	nameSegments.emplace_back(nameSegment);
	return NamedType(cls, std::move(nameSegments), width, isSigned);
}

DemangledTypeNode DemangledTypeNode::NamedType(BNNamedTypeReferenceClass cls,
	DemangledQualifiedName nameSegments, size_t width, bool isSigned)
{
	DemangledTypeNode n;
	n.m_payload = NamedTypePayload{cls, std::move(nameSegments), width, FixedWidth, isSigned};
	return n;
}

DemangledTypeNode DemangledTypeNode::NamedType(StringList nameSegments, size_t width, bool isSigned)
{
	return NamedType(UnknownNamedTypeClass, std::move(nameSegments), width, isSigned);
}

DemangledTypeNode DemangledTypeNode::NamedType(std::string_view nameSegment, size_t width, bool isSigned)
{
	return NamedType(UnknownNamedTypeClass, nameSegment, width, isSigned);
}

DemangledTypeNode DemangledTypeNode::NamedType(DemangledQualifiedName nameSegments, size_t width, bool isSigned)
{
	return NamedType(UnknownNamedTypeClass, std::move(nameSegments), width, isSigned);
}

DemangledTypeNode DemangledTypeNode::PostfixType(NodeRef child, string suffix)
{
	DemangledTypeNode n;
	n.m_payload = PostfixPayload{std::move(child), std::move(suffix), nullptr};
	return n;
}


DemangledTypeNode DemangledTypeNode::PostfixType(NodeRef child, string separator, NodeRef suffixType)
{
	DemangledTypeNode n = PostfixType(std::move(child), std::move(separator));
	if (auto payload = std::get_if<PostfixPayload>(&n.m_payload))
		payload->suffixType = std::move(suffixType);
	return n;
}


DemangledTypeNode DemangledTypeNode::UnaryExpression(string op, NodeRef child)
{
	DemangledTypeNode n;
	n.m_payload = UnaryExpressionPayload{std::move(op), std::move(child)};
	return n;
}


DemangledTypeNode DemangledTypeNode::BinaryExpression(NodeRef left, string op, NodeRef right)
{
	DemangledTypeNode n;
	n.m_payload = BinaryExpressionPayload{std::move(left), std::move(op), std::move(right)};
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


size_t DemangledTypeNode::ResolveWidth(size_t width, WidthKind widthKind, const Platform& platform)
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
	case 12:
	case 13:
		// Internal expression rendering forms report as named types so they can be carried as template args.
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
	if (auto payload = std::get_if<UnaryExpressionPayload>(&m_payload))
		return payload->childType;
	if (auto payload = std::get_if<BinaryExpressionPayload>(&m_payload))
		return payload->leftType;
	return nullptr;
}


bool DemangledTypeNode::MutateChildTypes(const std::function<bool(DemangledTypeNode&)>& mutator)
{
	bool changed = false;
	auto mutateRef = [&](NodeRef& typeRef) {
		if (!typeRef)
			return;
		DemangledTypeNode mutableType = *typeRef;
		if (mutator(mutableType))
		{
			typeRef = CreateShared(std::move(mutableType));
			changed = true;
		}
	};

	if (auto payload = std::get_if<PointerPayload>(&m_payload))
		mutateRef(payload->childType);
	else if (auto payload = std::get_if<MemberPointerPayload>(&m_payload))
		mutateRef(payload->childType);
	else if (auto payload = std::get_if<ArrayPayload>(&m_payload))
		mutateRef(payload->childType);
	else if (auto payload = std::get_if<FunctionPayload>(&m_payload))
	{
		mutateRef(payload->returnType);
		mutateRef(payload->implicitThisParameterType);
		for (auto& param: payload->params)
			mutateRef(param.type);
	}
	else if (auto payload = std::get_if<PostfixPayload>(&m_payload))
	{
		mutateRef(payload->childType);
		mutateRef(payload->suffixType);
	}
	else if (auto payload = std::get_if<UnaryExpressionPayload>(&m_payload))
	{
		mutateRef(payload->childType);
	}
	else if (auto payload = std::get_if<BinaryExpressionPayload>(&m_payload))
	{
		mutateRef(payload->leftType);
		mutateRef(payload->rightType);
	}
	return changed;
}


bool DemangledTypeNode::MutateQualifiedNames(const std::function<bool(DemangledQualifiedName&)>& mutator)
{
	if (auto payload = std::get_if<MemberPointerPayload>(&m_payload))
		return mutator(payload->ownerName);
	else if (auto payload = std::get_if<NamedTypePayload>(&m_payload))
		return mutator(payload->name);
	return false;
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
	if (childType->use_count() > 1)
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
	BN_ASSERT(false && "GetMutableName called for non-named demangled type");
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
	BN_ASSERT(false && "SetName called for non-named demangled type");
}


BNNamedTypeReferenceClass DemangledTypeNode::GetNTRClass() const
{
	if (auto payload = std::get_if<NamedTypePayload>(&m_payload))
		return payload->ntrClass;
	return UnknownNamedTypeClass;
}


bool DemangledTypeNode::GetIntegerTypeInfo(size_t& width, WidthKind& widthKind, bool& isSigned,
	std::string_view& altName) const
{
	width = 0;
	widthKind = FixedWidth;
	isSigned = false;
	altName = {};
	if (auto payload = std::get_if<IntegerPayload>(&m_payload))
	{
		width = payload->width;
		widthKind = payload->widthKind;
		isSigned = payload->isSigned;
		altName = std::string_view(payload->altName.data(), payload->altName.size());
		return true;
	}
	return false;
}


bool DemangledTypeNode::GetWideCharTypeInfo(size_t& width, std::string_view& altName) const
{
	width = 0;
	altName = {};
	if (auto payload = std::get_if<WideCharPayload>(&m_payload))
	{
		width = payload->width;
		altName = std::string_view(payload->altName.data(), payload->altName.size());
		return true;
	}
	return false;
}


bool DemangledTypeNode::GetPointerChildType(const DemangledTypeNode*& childType, BNReferenceType& referenceType) const
{
	childType = nullptr;
	referenceType = PointerReferenceType;
	if (auto payload = std::get_if<PointerPayload>(&m_payload))
	{
		childType = payload->childType.get();
		referenceType = payload->referenceType;
		return true;
	}
	return false;
}


void DemangledTypeNode::SetNTRType(BNNamedTypeReferenceClass cls)
{
	if (auto payload = std::get_if<NamedTypePayload>(&m_payload))
	{
		payload->ntrClass = cls;
		return;
	}
	BN_ASSERT(false && "SetNTRType called for non-named demangled type");
}


void DemangledTypeNode::SetParenthesizedMemberPointer(bool parenthesized)
{
	if (auto payload = std::get_if<MemberPointerPayload>(&m_payload))
	{
		payload->parenthesized = parenthesized;
		return;
	}
	BN_ASSERT(false && "SetParenthesizedMemberPointer called for non-member-pointer demangled type");
}


void DemangledTypeNode::SetCallingConventionName(BNCallingConventionName cc)
{
	if (auto payload = std::get_if<FunctionPayload>(&m_payload))
	{
		payload->callingConventionName = cc;
		return;
	}
	BN_ASSERT(false && "SetCallingConventionName called for non-function demangled type");
}


bool DemangledTypeNode::HasTemplateArguments() const
{
	if (const auto* payload = std::get_if<NamedTypePayload>(&m_payload))
		return std::ranges::any_of(payload->name, &DemangledNamePart::HasTemplateArguments);
	if (const auto* payload = std::get_if<UnaryExpressionPayload>(&m_payload))
		return payload->childType && payload->childType->HasTemplateArguments();
	if (const auto* payload = std::get_if<BinaryExpressionPayload>(&m_payload))
		return (payload->leftType && payload->leftType->HasTemplateArguments()) ||
			(payload->rightType && payload->rightType->HasTemplateArguments());
	return false;
}


bool DemangledTypeNode::ContainsNodeRef(const NodeRef& target) const
{
	if (!target)
		return false;

	std::unordered_set<const DemangledTypeNode*> visited;
	std::function<bool(const DemangledTypeNode*)> containsNode;
	std::function<bool(const NodeRef&)> containsRef;

	containsRef = [&](const NodeRef& ref) {
		if (!ref)
			return false;
		if (ref == target)
			return true;
		return containsNode(ref.get());
	};

	auto containsName = [&](const DemangledQualifiedName& name) {
		for (const auto& part : name)
		{
			if (containsRef(part.m_baseTypeSuffix))
				return true;
			for (const auto& arg : part.m_templateArgs)
			{
				if (containsRef(arg.type))
					return true;
			}
		}
		return false;
	};

	auto containsParams = [&](const vector<Param>& params) {
		for (const auto& param : params)
		{
			if (containsRef(param.type))
				return true;
		}
		return false;
	};

	containsNode = [&](const DemangledTypeNode* node) {
		if (!node)
			return false;
		if (node == target.get())
			return true;
		if (!visited.insert(node).second)
			return false;

		if (auto payload = std::get_if<PointerPayload>(&node->m_payload))
			return containsRef(payload->childType);
		if (auto payload = std::get_if<MemberPointerPayload>(&node->m_payload))
			return containsRef(payload->childType) || containsName(payload->ownerName);
		if (auto payload = std::get_if<ArrayPayload>(&node->m_payload))
			return containsRef(payload->childType);
		if (auto payload = std::get_if<FunctionPayload>(&node->m_payload))
		{
			return containsRef(payload->returnType) || containsRef(payload->implicitThisParameterType) ||
				containsParams(payload->params);
		}
		if (auto payload = std::get_if<NamedTypePayload>(&node->m_payload))
			return containsName(payload->name);
		if (auto payload = std::get_if<PostfixPayload>(&node->m_payload))
			return containsRef(payload->childType) || containsRef(payload->suffixType);
		if (auto payload = std::get_if<UnaryExpressionPayload>(&node->m_payload))
			return containsRef(payload->childType);
		if (auto payload = std::get_if<BinaryExpressionPayload>(&node->m_payload))
			return containsRef(payload->leftType) || containsRef(payload->rightType);
		return false;
	};

	return containsNode(this);
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

	if (std::get_if<VoidPayload>(&m_payload))
		return std::get_if<VoidPayload>(&other.m_payload);
	if (std::get_if<BoolPayload>(&m_payload))
		return std::get_if<BoolPayload>(&other.m_payload);
	if (std::get_if<VarArgsPayload>(&m_payload))
		return std::get_if<VarArgsPayload>(&other.m_payload);
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
	if (auto payload = std::get_if<UnaryExpressionPayload>(&m_payload))
	{
		auto otherPayload = std::get_if<UnaryExpressionPayload>(&other.m_payload);
		return otherPayload && payload->op == otherPayload->op &&
			typePtrsEqual(payload->childType, otherPayload->childType);
	}
	if (auto payload = std::get_if<BinaryExpressionPayload>(&m_payload))
	{
		auto otherPayload = std::get_if<BinaryExpressionPayload>(&other.m_payload);
		return otherPayload && payload->op == otherPayload->op &&
			typePtrsEqual(payload->leftType, otherPayload->leftType) &&
			typePtrsEqual(payload->rightType, otherPayload->rightType);
	}

	return false;
}


StringList DemangledTypeNode::RenderTypeNameSegments(Platform& platform) const
{
	StringList result;
	if (std::get_if<PostfixPayload>(&m_payload))
	{
		result.push_back(GetString(platform));
		return result;
	}
	if (std::get_if<UnaryExpressionPayload>(&m_payload))
	{
		result.push_back(GetString(platform));
		return result;
	}
	if (std::get_if<BinaryExpressionPayload>(&m_payload))
	{
		result.push_back(GetString(platform));
		return result;
	}
	if (auto payload = std::get_if<NamedTypePayload>(&m_payload))
	{
		result.reserve(payload->name.size());
		for (const auto& segment: payload->name)
			result.push_back(segment.GetString(platform));
	}
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


void DemangledTypeNode::AppendPostfixType(string& out, Platform& platform) const
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


void DemangledTypeNode::AppendUnaryExpression(string& out, Platform& platform) const
{
	const auto* payload = std::get_if<UnaryExpressionPayload>(&m_payload);
	if (!payload)
		return;
	out += payload->op;
	out += '(';
	if (payload->childType)
		payload->childType->AppendString(out, platform);
	out += ')';
}


void DemangledTypeNode::AppendBinaryExpression(string& out, Platform& platform) const
{
	const auto* payload = std::get_if<BinaryExpressionPayload>(&m_payload);
	if (!payload)
		return;
	out += '(';
	if (payload->leftType)
		payload->leftType->AppendString(out, platform);
	out += ") ";
	out += payload->op;
	out += " (";
	if (payload->rightType)
		payload->rightType->AppendString(out, platform);
	out += ')';
}


void DemangledTypeNode::AppendModifiers(string& out) const
{
	if (m_const)
		out += " const";
	if (m_volatile)
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
	string& out, const DemangledQualifiedName& name, Platform& platform)
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


void DemangledTypeNode::AppendTypeName(string& out, Platform& platform) const
{
	if (auto payload = std::get_if<NamedTypePayload>(&m_payload))
		AppendNamePartList(out, payload->name, platform);
}


string DemangledTypeNode::GetStringBeforeName(Platform& platform) const
{
	string out;
	AppendBeforeName(out, nullptr, platform);
	return out;
}


string DemangledTypeNode::GetStringAfterName(Platform& platform) const
{
	string out;
	AppendAfterName(out, nullptr, platform);
	return out;
}


void DemangledTypeNode::AppendBeforeName(string& out, const DemangledTypeNode* parentType, Platform& platform) const
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
		if (std::get_if<UnaryExpressionPayload>(&m_payload))
		{
			AppendUnaryExpression(out, platform);
			AppendModifiers(out);
			break;
		}
		if (std::get_if<BinaryExpressionPayload>(&m_payload))
		{
			AppendBinaryExpression(out, platform);
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


void DemangledTypeNode::AppendAfterName(string& out, const DemangledTypeNode* parentType, Platform& platform) const
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
		out += fmt::format("[{:#x}]", payload.elements);
		if (payload.childType)
			payload.childType->AppendAfterName(out, this, platform);
		break;
	}
	default:
		break;
	}
}


void DemangledTypeNode::AppendString(string& out, Platform& platform) const
{
	AppendBeforeName(out, nullptr, platform);
	size_t beforeEnd = out.size(); // track where "before" ends

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


string DemangledTypeNode::GetString(Platform& platform) const
{
	string out;
	AppendString(out, platform);
	return out;
}


string DemangledTypeNode::GetTypeAndName(const StringList& name, Platform& platform) const
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
	if (std::holds_alternative<UnaryExpressionPayload>(m_payload))
		return true;
	if (std::holds_alternative<BinaryExpressionPayload>(m_payload))
		return true;
	if (auto payload = std::get_if<ArrayPayload>(&m_payload))
		return payload->childType && payload->childType->HasUndeterminedTopLevelSize();
	return false;
}


uint8_t DemangledTypeNode::GetValueConfidence() const
{
	return HasUndeterminedTopLevelSize() ? BN_DEFAULT_CONFIDENCE : BN_FULL_CONFIDENCE;
}


Ref<Type> DemangledTypeNode::Finalize(Platform& platform) const
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
			finalParams.emplace_back("this", thisType->WithConfidence(payload.implicitThisParameterType->GetValueConfidence()),
				DefaultLocationSource, Variable());
		}
		for (auto& p : payload.params)
		{
			Ref<Type> pType = p.type ? p.type->Finalize(platform) : Ref<Type>(Type::VoidType());
			uint8_t pTypeConfidence = p.type ? p.type->GetValueConfidence() : BN_FULL_CONFIDENCE;
			finalParams.emplace_back(p.name, pType->WithConfidence(pTypeConfidence), DefaultLocationSource, Variable());
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
		if (std::get_if<PostfixPayload>(&m_payload) || std::get_if<UnaryExpressionPayload>(&m_payload) ||
			std::get_if<BinaryExpressionPayload>(&m_payload))
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
