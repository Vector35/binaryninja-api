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

#pragma once

#ifdef BINARYNINJACORE_LIBRARY
#include "type.h"
#include "architecture.h"
#ifndef BN
#define BN BinaryNinjaCore
#endif
#ifndef _STD_STRING
#define _STD_STRING BinaryNinjaCore::string
#endif
#ifndef _STD_VECTOR
#define _STD_VECTOR BinaryNinjaCore::vector
#endif
#else
#include "binaryninjaapi.h"
#ifndef BN
#define BN BinaryNinja
#endif
#ifndef _STD_STRING
#define _STD_STRING std::string
#endif
#ifndef _STD_VECTOR
#define _STD_VECTOR std::vector
#endif
#endif

#include <functional>
#include <memory>
#include <string_view>
#include <variant>

#ifdef BINARYNINJACORE_LIBRARY
namespace BinaryNinjaCore { class Platform; }
#else
namespace BinaryNinja { class Platform; }
#endif

using StringList = _STD_VECTOR<_STD_STRING>;

BN::Platform& GetDemanglerFallbackPlatform();

class DemangledTypeNode;

struct DemangledTypeNodeParam
{
	_STD_STRING name;
	std::shared_ptr<DemangledTypeNode> type = nullptr;
};

class DemangledNamePart
{
public:
	using Ref = std::shared_ptr<DemangledNamePart>;

	DemangledNamePart();
	explicit DemangledNamePart(_STD_STRING base);
	explicit DemangledNamePart(const char* base);
	explicit DemangledNamePart(std::string_view base);
	DemangledNamePart(_STD_STRING base, std::shared_ptr<DemangledTypeNode> baseTypeSuffix);
	DemangledNamePart(_STD_STRING base, _STD_VECTOR<DemangledTypeNodeParam> templateArgs,
		bool spaceAfterComma = false);

	[[nodiscard]] const _STD_STRING& GetBase() const { return m_base; }
	void SetBase(_STD_STRING base) { m_base = std::move(base); }
	void AppendBase(const _STD_STRING& suffix) { m_base += suffix; }
	void AppendBase(std::string_view suffix)
	{
		if (!suffix.empty())
			m_base.append(suffix.data(), suffix.size());
	}
	[[nodiscard]] bool HasTemplateArguments() const { return m_hasTemplateArgs || !m_templateArgs.empty(); }
	[[nodiscard]] const _STD_VECTOR<DemangledTypeNodeParam>& GetTemplateArguments() const { return m_templateArgs; }
	_STD_VECTOR<DemangledTypeNodeParam>& GetMutableTemplateArguments() { return m_templateArgs; }
	void SetTemplateArguments(_STD_VECTOR<DemangledTypeNodeParam> args, bool spaceAfterComma = false);
	void ClearTemplateArguments();

	void AppendString(_STD_STRING& out, BN::Platform& platform) const;
	_STD_STRING GetString(BN::Platform& platform = GetDemanglerFallbackPlatform()) const;
	[[nodiscard]] bool IsStructurallyEqual(const DemangledNamePart& other) const;

	static Ref CreateShared(DemangledNamePart part);
	static Ref CreateSharedCopy(const DemangledNamePart& part);

private:
	friend class DemangledTypeNode;

	_STD_STRING m_base;
	std::shared_ptr<DemangledTypeNode> m_baseTypeSuffix;
	_STD_VECTOR<DemangledTypeNodeParam> m_templateArgs;
	bool m_hasTemplateArgs;
	bool m_spaceAfterTemplateComma;
};

using DemangledQualifiedName = _STD_VECTOR<DemangledNamePart>;

// Lightweight type representation for demanglers (GNU3 and MSVC).
// This object serves as an abstraction layer between C++'s type system and our own.
// It also removes a source of a lot of reallocation of NamedTypeReference BinaryNinja::Type objects
// and only creates real Type objects when Finalize() is called.
class DemangledTypeNode
{
public:
	using NodeRef = std::shared_ptr<DemangledTypeNode>;
	using Param = DemangledTypeNodeParam;

	enum WidthKind : uint8_t
	{
		FixedWidth,
		AddressWidth,
		DefaultIntegerWidth
	};

	DemangledTypeNode();
	DemangledTypeNode(const DemangledTypeNode&) = default;
	DemangledTypeNode(DemangledTypeNode&&) = default;
	DemangledTypeNode& operator=(const DemangledTypeNode&) = default;
	DemangledTypeNode& operator=(DemangledTypeNode&&) = default;

	// Static factory methods matching TypeBuilder's interface
	static DemangledTypeNode VoidType();
	static DemangledTypeNode BoolType();
	static DemangledTypeNode IntegerType(size_t width, bool isSigned, const _STD_STRING& altName = "");
	static DemangledTypeNode AddressSizedIntegerType(bool isSigned, const _STD_STRING& altName = "");
	static DemangledTypeNode FloatType(size_t width, const _STD_STRING& altName = "");
	static DemangledTypeNode WideCharType(size_t width, const _STD_STRING& altName = "");
	static DemangledTypeNode VarArgsType();
	static DemangledTypeNode PointerType(DemangledTypeNode child, bool cnst, bool vltl, BNReferenceType refType);
	static DemangledTypeNode PointerType(NodeRef child, bool cnst, bool vltl, BNReferenceType refType);
	static DemangledTypeNode MemberPointerType(DemangledTypeNode child, DemangledQualifiedName ownerName,
		bool cnst, bool vltl);
	static DemangledTypeNode MemberPointerType(NodeRef child, DemangledQualifiedName ownerName,
		bool cnst, bool vltl);
	static DemangledTypeNode ArrayType(DemangledTypeNode child, uint64_t count);
	static DemangledTypeNode ArrayType(NodeRef child, uint64_t count);
	static DemangledTypeNode FunctionType(DemangledTypeNode retType,
		std::nullptr_t, _STD_VECTOR<Param> params);
	static DemangledTypeNode FunctionType(NodeRef retType,
		std::nullptr_t, _STD_VECTOR<Param> params);
	static DemangledTypeNode NamedType(BNNamedTypeReferenceClass cls,
		StringList nameSegments, size_t width = 0, bool isSigned = false);
	static DemangledTypeNode NamedType(BNNamedTypeReferenceClass cls,
		std::string_view nameSegment, size_t width = 0, bool isSigned = false);
	static DemangledTypeNode NamedType(BNNamedTypeReferenceClass cls,
		DemangledQualifiedName nameSegments, size_t width = 0, bool isSigned = false);
	// Use when the mangling provides a name but not a struct/class/union/enum kind.
	static DemangledTypeNode NamedType(StringList nameSegments, size_t width = 0, bool isSigned = false);
	static DemangledTypeNode NamedType(std::string_view nameSegment, size_t width = 0, bool isSigned = false);
	static DemangledTypeNode NamedType(DemangledQualifiedName nameSegments, size_t width = 0, bool isSigned = false);
	static DemangledTypeNode PostfixType(NodeRef child, _STD_STRING suffix);
	static DemangledTypeNode PostfixType(NodeRef child, _STD_STRING separator, NodeRef suffixType);
	static DemangledTypeNode UnaryExpression(_STD_STRING op, NodeRef child);
	static DemangledTypeNode BinaryExpression(NodeRef left, _STD_STRING op, NodeRef right);
	static NodeRef CreateShared(DemangledTypeNode node);
	static NodeRef CreateSharedCopy(const DemangledTypeNode& node);

	[[nodiscard]] BNTypeClass GetClass() const { return GetPayloadClass(); }
	[[nodiscard]] const DemangledQualifiedName& GetName() const;
	[[nodiscard]] DemangledQualifiedName& GetMutableName();
	[[nodiscard]] bool IsConst() const { return m_const; }
	[[nodiscard]] bool IsVolatile() const { return m_volatile; }
	[[nodiscard]] BNNameType GetNameType() const { return m_nameType; }
	[[nodiscard]] bool HasTemplateArguments() const;
	[[nodiscard]] uint8_t GetPointerSuffixBits() const { return m_pointerSuffixBits; }
	[[nodiscard]] BNNamedTypeReferenceClass GetNTRClass() const;
	bool GetIntegerTypeInfo(size_t& width, WidthKind& widthKind, bool& isSigned, std::string_view& altName) const;
	bool GetWideCharTypeInfo(size_t& width, std::string_view& altName) const;
	bool GetPointerChildType(const DemangledTypeNode*& childType, BNReferenceType& referenceType) const;
	void SetParenthesizedMemberPointer(bool parenthesized);
	[[nodiscard]] StringList RenderTypeNameSegments(BN::Platform& platform = GetDemanglerFallbackPlatform()) const;
	[[nodiscard]] bool IsStructurallyEqual(const DemangledTypeNode& other) const;
	[[nodiscard]] bool ContainsNodeRef(const NodeRef& target) const;
	bool MutateChildTypes(const std::function<bool(DemangledTypeNode&)>& mutator);
	bool MutateQualifiedNames(const std::function<bool(DemangledQualifiedName&)>& mutator);

	void SetName(DemangledQualifiedName name);
	void SetConst(bool c) { m_const = c; }
	void SetVolatile(bool v) { m_volatile = v; }
	void SetNameType(BNNameType nt) { m_nameType = nt; }
	void SetPointerSuffixBits(uint8_t bits) { m_pointerSuffixBits = bits; }
	void AddPointerSuffixBits(uint8_t bits) { m_pointerSuffixBits |= bits; }
	void AddPointerSuffix(BNPointerSuffix ps) { m_pointerSuffixBits |= PointerSuffixBit(ps); }
	bool AddQualifiersToPointerChild(bool cnst, bool vltl);
	void SetReturnTypeConfidence(uint8_t c) { m_returnTypeConfidence = c; }
	void SetCallingConventionName(BNCallingConventionName cc);
	void SetNTRType(BNNamedTypeReferenceClass cls);
	void SetImplicitThisParameter(DemangledTypeNode type);

	void AppendString(_STD_STRING& out, BN::Platform& platform) const;
	_STD_STRING GetString(BN::Platform& platform = GetDemanglerFallbackPlatform()) const;
	_STD_STRING GetStringBeforeName(BN::Platform& platform = GetDemanglerFallbackPlatform()) const;
	_STD_STRING GetStringAfterName(BN::Platform& platform = GetDemanglerFallbackPlatform()) const;
	_STD_STRING GetTypeAndName(const StringList& name, BN::Platform& platform = GetDemanglerFallbackPlatform()) const;

	BN::Ref<BN::Type> Finalize(BN::Platform& platform = GetDemanglerFallbackPlatform()) const;

private:
	struct VoidPayload {};
	struct BoolPayload {};
	struct VarArgsPayload {};

	struct IntegerPayload
	{
		size_t width = 0;
		WidthKind widthKind = FixedWidth;
		bool isSigned = false;
		_STD_STRING altName;
	};

	struct FloatPayload
	{
		size_t width = 0;
		_STD_STRING altName;
	};

	struct WideCharPayload
	{
		size_t width = 0;
		_STD_STRING altName;
	};

	struct PointerPayload
	{
		NodeRef childType;
		BNReferenceType referenceType = PointerReferenceType;
	};

	struct MemberPointerPayload
	{
		NodeRef childType;
		DemangledQualifiedName ownerName;
		bool parenthesized = false;
	};

	struct ArrayPayload
	{
		NodeRef childType;
		uint64_t elements = 0;
	};

	struct FunctionPayload
	{
		NodeRef returnType;
		_STD_VECTOR<Param> params;
		NodeRef implicitThisParameterType;
		BNCallingConventionName callingConventionName = NoCallingConvention;
	};

	struct NamedTypePayload
	{
		BNNamedTypeReferenceClass ntrClass = UnknownNamedTypeClass;
		DemangledQualifiedName name;
		size_t width = 0;
		WidthKind widthKind = FixedWidth;
		bool isSigned = false;
	};

	struct PostfixPayload
	{
		NodeRef childType;
		_STD_STRING suffix;
		NodeRef suffixType;
	};

	struct UnaryExpressionPayload
	{
		_STD_STRING op;
		NodeRef childType;
	};

	struct BinaryExpressionPayload
	{
		NodeRef leftType;
		_STD_STRING op;
		NodeRef rightType;
	};

	using Payload = std::variant<
		VoidPayload,
		BoolPayload,
		IntegerPayload,
		FloatPayload,
		WideCharPayload,
		VarArgsPayload,
		PointerPayload,
		MemberPointerPayload,
		ArrayPayload,
		FunctionPayload,
		NamedTypePayload,
		PostfixPayload,
		UnaryExpressionPayload,
		BinaryExpressionPayload>;

	[[nodiscard]] bool HasUndeterminedTopLevelSize() const;
	[[nodiscard]] uint8_t GetValueConfidence() const;
	[[nodiscard]] BNTypeClass GetPayloadClass() const;
	[[nodiscard]] NodeRef GetPrimaryChild() const;
	static size_t ResolveWidth(size_t width, WidthKind widthKind, const BN::Platform& platform = GetDemanglerFallbackPlatform());

	BNNameType m_nameType;
	uint8_t m_pointerSuffixBits;
	uint8_t m_returnTypeConfidence;
	bool m_const;
	bool m_volatile;
	Payload m_payload;

	// Helpers for string formatting
	static uint8_t PointerSuffixBit(BNPointerSuffix ps);
	void AddPointerSuffixes(BN::TypeBuilder& tb, bool omitPtr64 = true) const;
	[[nodiscard]] bool HasPostfixType() const;
	void AppendPostfixType(_STD_STRING& out, BN::Platform& platform) const;
	void AppendUnaryExpression(_STD_STRING& out, BN::Platform& platform) const;
	void AppendBinaryExpression(_STD_STRING& out, BN::Platform& platform) const;
	void AppendModifiers(_STD_STRING& out) const;
	void AppendPointerSuffix(_STD_STRING& out) const;
	static void AppendNamePartList(_STD_STRING& out, const DemangledQualifiedName& name,
		BN::Platform& platform);
	void AppendTypeName(_STD_STRING& out, BN::Platform& platform) const;
	void AppendBeforeName(_STD_STRING& out, const DemangledTypeNode* parentType, BN::Platform& platform) const;
	void AppendAfterName(_STD_STRING& out, const DemangledTypeNode* parentType, BN::Platform& platform) const;
};
