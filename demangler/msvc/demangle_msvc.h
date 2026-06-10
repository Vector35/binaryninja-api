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
#include <exception>
#include <optional>
#include <utility>

// XXX: Compiled directly into the core for performance reasons
// Will still work fine compiled independently, just at about a
// 50-100% performance penalty due to FFI overhead
#ifdef BINARYNINJACORE_LIBRARY
#include "qualifiedname.h"
#include "type.h"
#include "architecture.h"
#include "binaryview.h"
#include "demangle.h"
#define BN BinaryNinjaCore
#define _STD_STRING BinaryNinjaCore::string
#define _STD_VECTOR BinaryNinjaCore::vector
#else
#include "binaryninjaapi.h"
#define BN BinaryNinja
#define _STD_STRING std::string
#define _STD_VECTOR std::vector
#endif

#include "demangler/demangled_type_node.h"

class DemangleException: public std::exception
{
	_STD_STRING m_message;
public:
	DemangleException(_STD_STRING msg="Attempt to read beyond bounds or missing expected character"): m_message(std::move(msg)){}
	[[nodiscard]] const char* what() const noexcept override { return m_message.c_str(); }
};


class Demangle
{
	enum FunctionClass
	{
		NoneFunctionClass           = 0,
		PrivateFunctionClass        = 1 << 0,
		ProtectedFunctionClass      = 1 << 1,
		PublicFunctionClass         = 1 << 2,
		GlobalFunctionClass         = 1 << 3,
		StaticFunctionClass         = 1 << 4,
		VirtualFunctionClass        = 1 << 5,
		FriendFunctionClass         = 1 << 6,
		StaticThunkFunctionClass    = 1 << 7,
		VirtualThunkFunctionClass   = 1 << 8,
		VirtualThunkExFunctionClass = 1 << 9,
	};

public:
	struct DemangleContext
	{
		DemangledQualifiedName name;
		DemangledTypeNode type;
		BNMemberAccess access;
		BNMemberScope scope;
	};

private:
	class Reader
	{
	public:
		Reader(const _STD_STRING& data)
		{
			Reset(data);
		}
		void Reset(const _STD_STRING& data)
		{
			m_ptr = data.c_str();
			m_end = data.c_str() + data.size();
			ValidatePrintableAscii();
		}
		bool PeekMatch(const char* str, size_t len) const
		{
			if (len > Length())
				return false;
			return memcmp(m_ptr, str, len) == 0;
		}
		[[nodiscard]] char PeekAt(size_t offset) const
		{
			if (offset >= Length())
				throw DemangleException();
			return m_ptr[offset];
		}
		[[nodiscard]] char Peek() const
		{
			if (m_ptr >= m_end)
				throw DemangleException();
			return *m_ptr;
		}
		[[nodiscard]] char PeekOr(char fallback = '\0') const
		{
			if (Length() == 0)
				return fallback;
			return *m_ptr;
		}
		[[nodiscard]] const char* GetRaw() const { return m_ptr; }
		void SetRaw(const char* p) { m_ptr = p; }
		[[nodiscard]] char Read()
		{
			if (m_ptr >= m_end)
				throw DemangleException();
			return *m_ptr++;
		}
		bool ConsumeIf(char ch)
		{
			if (PeekOr() != ch)
				return false;
			Consume();
			return true;
		}
		bool ConsumeIf(const char* str, size_t len)
		{
			if (!PeekMatch(str, len))
				return false;
			Consume(len);
			return true;
		}
		template <size_t N>
		bool ConsumeIf(const char (&str)[N])
		{
			return ConsumeIf(str, N - 1);
		}
		void Consume(size_t count = 1)
		{
			if (count > Length())
				throw DemangleException();
			m_ptr += count;
		}
		[[nodiscard]] size_t Length() const { return static_cast<size_t>(m_end - m_ptr); }
		_STD_STRING ReadString(size_t count);
		_STD_STRING ReadUntil(char sentinel);
	private:
		void ValidatePrintableAscii() const
		{
			for (const char* p = m_ptr; p < m_end; p++)
				if (*p < 0x20 || *p > 0x7e)
					throw DemangleException();
		}
		const char* m_ptr;
		const char* m_end;
	};

	class BackrefList
	{
	public:
		_STD_VECTOR<DemangledTypeNode::NodeRef> typeList;
		_STD_VECTOR<DemangledNamePart::Ref> nameList;
		_STD_VECTOR<DemangledNamePart::Ref> templateList;
		void Clear() { typeList.clear(); nameList.clear(); templateList.clear(); }
		DemangledTypeNode::NodeRef GetTypeBackrefRef(size_t reference);
		DemangledNamePart::Ref GetNameBackrefRef(size_t reference);
		const DemangledTypeNode& GetTypeBackref(size_t reference);
		const DemangledNamePart& GetNameBackref(size_t reference);
		DemangledTypeNode::NodeRef PushTypeBackref(DemangledTypeNode::NodeRef t);
		DemangledTypeNode::NodeRef PushTypeBackref(const DemangledTypeNode& t);
		DemangledTypeNode::NodeRef PushTypeBackref(DemangledTypeNode&& t);
		DemangledNamePart::Ref PushNameBackref(DemangledNamePart::Ref t);
		DemangledNamePart::Ref PushNameBackref(const DemangledNamePart& t);
		DemangledNamePart::Ref PushNameBackref(DemangledNamePart&& t);
		DemangledNamePart::Ref PushTemplateSpecialization(DemangledNamePart::Ref t);
		DemangledNamePart::Ref PushTemplateSpecialization(const DemangledNamePart& t);
		DemangledNamePart::Ref PushTemplateSpecialization(DemangledNamePart&& t);
	};

	struct BackrefContextSwitch
	{
		BackrefList& active;
		BackrefList saved;

		BackrefContextSwitch(BackrefList& active);
		BackrefContextSwitch(const BackrefContextSwitch&) = delete;
		BackrefContextSwitch& operator=(const BackrefContextSwitch&) = delete;
		~BackrefContextSwitch();

		static void Swap(BackrefList& left, BackrefList& right);
	};

	// Internal name list type - keeps template names structured during parsing.
	using NameList = _STD_VECTOR<DemangledNamePart>;

	static DemangledNamePart MakeNameSegment(const _STD_STRING& s)
	{
		return DemangledNamePart(s);
	}

	static void AppendToLastNameSegment(NameList& nl, const _STD_STRING& suffix)
	{
		if (nl.empty())
			throw DemangleException();
		nl.back() = MakeNameSegment(nl.back().GetString() + suffix);
	}

	static _STD_STRING JoinNameList(const NameList& nl)
	{
		if (nl.empty()) return {};
		if (nl.size() == 1) return nl[0].GetString();

		size_t size = 2 * (nl.size() - 1);
		for (const auto& name : nl)
			size += name.GetString().size();

		_STD_STRING out;
		out.reserve(size);
		out = nl[0].GetString();
		for (size_t i = 1; i < nl.size(); i++)
		{
			out += ':';
			out += ':';
			out += nl[i].GetString();
		}
		return out;
	}

	static StringList FinalizeNameList(const NameList& nl)
	{
		StringList out;
		out.reserve(nl.size());
		for (const auto& n: nl)
			out.push_back(n.GetString());
		return out;
	}

	_STD_STRING m_mangledName; // Owns the string; Reader points into it
	Reader m_reader;
	BackrefList m_backrefList;
	BN::Architecture* m_arch;
	BN::Ref<BN::Platform> m_platform;
	BN::Ref<BN::BinaryView> m_view;
	size_t m_templateParamDepth = 0;
	size_t m_nestingDepth = 0;
	class NestingGuard
	{
		Demangle& m_demangler;
	public:
		NestingGuard(Demangle& demangler);
		~NestingGuard();
	};

	static void RewriteTemplateBackrefName(NameList& typeName, const BackrefList& nameBackrefList);
	static void PrependNameComponent(NameList& nameList, DemangledNamePart name);
	void AppendStringName(NameList& nameList, BackrefList& nameBackrefList);
	static void FinalizeConstructorTemplateName(NameList& nameList, size_t nameListSizeAtEntry, bool pending);
	static bool FunctionTypeHasPointerSuffix(char functionType);
	static _STD_STRING FormatFunctionScopeSignature(const DemangledTypeNode& type, const NameList& scopeName);
	void AppendLocalScope(NameList& nameList, BackrefList& nameBackrefList, uint64_t scopeOrdinal, bool typeNameContext);
	bool TryAppendLocalScopeAt(NameList& nameList, BackrefList& nameBackrefList, const char* encodedNumberStart,
		bool typeNameContext);
	_STD_STRING FormatTypeAndName(const DemangledTypeNode& type, const NameList& name) const;
	enum class TypeBackrefMode
	{
		RecordTopLevel,
		SuppressTopLevel,
	};
	struct EncodedNumber
	{
		uint64_t magnitude;
		bool negative;
	};
	enum class ThunkAdjustorKind
	{
		Static,
		Vtordisp,
		Vtordispex,
	};
	struct ThunkAdjustor
	{
		ThunkAdjustorKind kind = ThunkAdjustorKind::Static;
		uint64_t adjustor = 0;
		int32_t vbptrOffset = 0;
		int32_t vbOffsetOffset = 0;
		int32_t vtorDispOffset = 0;
		uint64_t staticOffset = 0;
	};
	struct DemangledFunction
	{
		DemangledTypeNode type;
		std::optional<ThunkAdjustor> thunkAdjustor;
	};
	static bool FunctionClassNeedsImplicitThis(int funcClass);
	static void AppendThunkAdjustorToName(NameList& nameList, const ThunkAdjustor& adjustor);
	static void SetImplicitThisParameter(DemangledTypeNode& type, BNNameType classFunctionType, const NameList& enclosingName);
	static void ApplySymbolFunctionContext(DemangledFunction& function, NameList& symbolName,
		BNNameType classFunctionType, int funcClass);
	DemangledTypeNode DemangleReferencedSymbolValue(BackrefList& varList);
	DemangledTypeNode DemangleAutoNonTypeTemplateParam(BackrefList& varList);
	DemangledTypeNode DemangleVarType(BackrefList& varList, bool isReturn,
		bool includeImplicitThis = true, DemangledTypeNode::NodeRef* outTypeBackref = nullptr,
		TypeBackrefMode typeBackrefMode = TypeBackrefMode::RecordTopLevel);
	EncodedNumber DecodeEncodedNumber();
	int64_t DecodeEncodedSignedNumber();
	uint64_t DecodeEncodedUnsignedNumber();
	int32_t DecodeEncodedSignedInt32();
	_STD_STRING DecodeEncodedNumberLiteral();
	char DemangleChar();
	void DemangleModifiers(bool& _const, bool& _volatile, bool& isMember);
	uint8_t DemanglePointerSuffix();
	void DemangleVariableList(_STD_VECTOR<DemangledTypeNode::Param>& paramList, BackrefList& varList, bool typeBackrefs = true);
	void DemangleTypeNameLookup(_STD_STRING& out, BNNameType& functionType);
	bool TryDemangleWinRTEscapedScopeName(NameList& nameList, BackrefList& nameBackrefList);
	void DemangleNameTypeString(_STD_STRING& out);
	void DemangleName(NameList& nameList,
	                  BNNameType& classFunctionType,
	                  BackrefList& nameBackrefList,
	                  bool typeNameContext = false);
	BNCallingConventionName DemangleCallingConvention();
	void ConsumeExtendedModifierPrefix();
	DemangledFunction DemangleFunction(BNNameType classFunctionType, bool pointerSuffix, BackrefList& varList,
		int funcClass = NoneFunctionClass);
	DemangledTypeNode DemangleData(BackrefList& varList);
	void DemangleNameTypeRtti(BNNameType& classFunctionType,
	                          BackrefList& nameBackrefList,
	                          _STD_STRING& out);
	DemangledTypeNode DemangleVTable(BackrefList& nameBackrefList, NameList& symbolName);
	DemangledTypeNode DemangleRTTI(BNNameType classFunctionType, const NameList& symbolName);
	DemangledNamePart DemangleTemplateInstantiationNameInLocalContext(BackrefList& nameBackrefList);
	DemangledNamePart DemangleTemplateInstantiationName(BackrefList& nameBackrefList);
	void DemangleTemplateParams(_STD_VECTOR<DemangledTypeNode::Param>& params, BackrefList& nameBackrefList, DemangledNamePart& out);
	DemangledNamePart DemangleUnqualifiedSymbolName(BackrefList& nameBackrefList, BNNameType& classFunctionType,
		bool& backrefEligible);
	DemangledTypeNode DemangleString(NameList& symbolName);
	DemangledTypeNode DemangleTypeInfoName(NameList& symbolName);
	DemangleContext DemangleDynamicInitFini(bool isDtor, BackrefList& backrefList);
	DemangleContext DemangleSymbol(BackrefList& backrefList);
	std::pair<BN::Ref<BN::Type>, BN::QualifiedName> Finalize(BN::BinaryView* view);

public:
	Demangle(BN::Architecture* arch, _STD_STRING  mangledName);
	Demangle(BN::Ref<BN::BinaryView> view, _STD_STRING  mangledName);
	Demangle(BN::Ref<BN::Platform> platform, _STD_STRING  mangledName);
	Demangle(const Demangle&) = delete;
	Demangle(Demangle&&) = delete;
	Demangle& operator=(const Demangle&) = delete;
	Demangle& operator=(Demangle&&) = delete;
	void Reset(BN::Architecture* arch, const _STD_STRING& mangledName);
	DemangleContext DemangleSymbol();
	std::pair<BN::Ref<BN::Type>, BN::QualifiedName> Finalize();

	// Be careful not to accidentally implicitly cast a BinaryView* to a bool
	static bool DemangleMS(BN::Architecture* arch, const _STD_STRING& mangledName, BN::Ref<BN::Type>& outType,
	                       BN::QualifiedName& outVarName, const BN::Ref<BN::BinaryView>& view);
	static bool DemangleMS(BN::Architecture* arch, const _STD_STRING& mangledName, BN::Ref<BN::Type>& outType,
	                       BN::QualifiedName& outVarName, BN::BinaryView* view);
	static bool DemangleMS(BN::Platform* platform, const _STD_STRING& mangledName, BN::Ref<BN::Type>& outType,
	                       BN::QualifiedName& outVarName);
	static bool DemangleMS(BN::Architecture* arch, const _STD_STRING& mangledName, BN::Ref<BN::Type>& outType,
	                       BN::QualifiedName& outVarName);

	static bool DemangleMS(const _STD_STRING& mangledName, BN::Ref<BN::Type>& outType,
	                       BN::QualifiedName& outVarName, const BN::Ref<BN::BinaryView>& view);
	static bool DemangleMS(const _STD_STRING& mangledName, BN::Ref<BN::Type>& outType,
	                       BN::QualifiedName& outVarName, BN::BinaryView* view);
};
